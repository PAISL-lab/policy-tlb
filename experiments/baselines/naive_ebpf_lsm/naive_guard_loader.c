// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/types.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include "include/common.h"
#include "include/event.h"
#include "naive_guard.skel.h"

#define BASELINE_PREFIX_LEN MCP_GUARD_RULE_VALUE_LEN

struct baseline_config {
	__u32 enforce;
	__u32 deny_port;
	char deny_exec_prefix[BASELINE_PREFIX_LEN];
	char deny_path_prefix[BASELINE_PREFIX_LEN];
};

static volatile sig_atomic_t exiting;

static void handle_signal(int signo)
{
	(void)signo;
	exiting = 1;
}

static int bump_memlock_rlimit(void)
{
	struct rlimit rlim = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	return setrlimit(RLIMIT_MEMLOCK, &rlim);
}

static const char *hook_name(__u32 hook)
{
	switch (hook) {
	case MCP_GUARD_HOOK_EXEC:
		return "exec";
	case MCP_GUARD_HOOK_FILE_OPEN:
		return "file_open";
	case MCP_GUARD_HOOK_FILE_READ:
		return "file_read";
	case MCP_GUARD_HOOK_FILE_WRITE:
		return "file_write";
	case MCP_GUARD_HOOK_SOCKET_CONNECT:
		return "socket_connect";
	default:
		return "unknown";
	}
}

static const char *layer_name(__u32 layer)
{
	switch (layer) {
	case MCP_GUARD_LAYER_L1:
		return "L1";
	case MCP_GUARD_LAYER_L2:
		return "L2";
	case MCP_GUARD_LAYER_L3:
		return "L3";
	default:
		return "unknown";
	}
}

static const char *action_name(__u32 action)
{
	switch (action) {
	case MCP_GUARD_ACTION_ALLOW:
		return "allow";
	case MCP_GUARD_ACTION_DENY:
		return "deny";
	case MCP_GUARD_ACTION_AUDIT:
		return "audit";
	default:
		return "unknown";
	}
}

static void decode_metric_index(__u32 index, __u32 *hook, __u32 *layer,
				__u32 *action)
{
	*hook = (index >> 5) & 0x7;
	*layer = (index >> 2) & 0x7;
	*action = index & 0x3;
}

static void copy_env_string(char *dst, size_t dst_size, const char *name,
			    const char *fallback)
{
	const char *value = getenv(name);

	if (!value || !value[0])
		value = fallback;
	snprintf(dst, dst_size, "%s", value ? value : "");
}

static __u32 env_u32(const char *name, __u32 fallback)
{
	const char *value = getenv(name);
	char *end = NULL;
	unsigned long parsed;

	if (!value || !value[0])
		return fallback;
	errno = 0;
	parsed = strtoul(value, &end, 0);
	if (errno || !end || *end)
		return fallback;
	return (__u32)parsed;
}

static int configure_policy(int config_fd)
{
	struct baseline_config cfg = {};
	__u32 key = 0;

	cfg.enforce = env_u32("NAIVE_EBPF_ENFORCE", 1);
	cfg.deny_port = env_u32("NAIVE_EBPF_DENY_PORT", 4444);
	copy_env_string(cfg.deny_exec_prefix, sizeof(cfg.deny_exec_prefix),
			"NAIVE_EBPF_DENY_EXEC_PREFIX", "/usr/bin/curl");
	copy_env_string(cfg.deny_path_prefix, sizeof(cfg.deny_path_prefix),
			"NAIVE_EBPF_DENY_PATH_PREFIX",
			"/tmp/mcpguard-baseline-deny");

	return bpf_map_update_elem(config_fd, &key, &cfg, BPF_ANY);
}

static int read_metric_slot(int metrics_fd, __u32 index,
			    struct mcp_metric_value *total)
{
	int cpus = libbpf_num_possible_cpus();
	struct mcp_metric_value *values;
	size_t value_size;

	if (cpus <= 0)
		return -EINVAL;

	value_size = sizeof(*values) * (size_t)cpus;
	values = calloc(1, value_size);
	if (!values)
		return -ENOMEM;

	if (bpf_map_lookup_elem(metrics_fd, &index, values) != 0) {
		free(values);
		return -errno;
	}

	memset(total, 0, sizeof(*total));
	for (int cpu = 0; cpu < cpus; cpu++) {
		struct mcp_metric_value *v = &values[cpu];

		total->count += v->count;
		total->total_ns += v->total_ns;
		if (v->min_ns && (!total->min_ns || v->min_ns < total->min_ns))
			total->min_ns = v->min_ns;
		if (v->max_ns > total->max_ns)
			total->max_ns = v->max_ns;
		for (__u32 b = 0; b < MCP_GUARD_HIST_BUCKETS; b++)
			total->buckets[b] += v->buckets[b];
	}

	free(values);
	return 0;
}

static void print_metrics_summary(int metrics_fd)
{
	__u64 total_count = 0;
	__u64 l1_count = 0;
	__u64 l2_count = 0;
	__u64 l3_count = 0;
	struct mcp_metric_value slots[MCP_GUARD_METRIC_SLOTS] = {};

	for (__u32 index = 0; index < MCP_GUARD_METRIC_SLOTS; index++) {
		__u32 hook;
		__u32 layer;
		__u32 action;

		if (read_metric_slot(metrics_fd, index, &slots[index]) != 0)
			continue;
		if (!slots[index].count)
			continue;

		decode_metric_index(index, &hook, &layer, &action);
		(void)hook;
		(void)action;
		total_count += slots[index].count;
		if (layer == MCP_GUARD_LAYER_L1)
			l1_count += slots[index].count;
		else if (layer == MCP_GUARD_LAYER_L2)
			l2_count += slots[index].count;
		else if (layer == MCP_GUARD_LAYER_L3)
			l3_count += slots[index].count;
	}

	printf("metrics summary:\n");
	if (total_count) {
		printf("metrics ratios: total=%llu L1=%.6f L2=%.6f L3=%.6f\n",
		       (unsigned long long)total_count,
		       (double)l1_count / (double)total_count,
		       (double)l2_count / (double)total_count,
		       (double)l3_count / (double)total_count);
	} else {
		printf("metrics ratios: total=0 L1=0.000000 L2=0.000000 L3=0.000000\n");
	}

	for (__u32 index = 0; index < MCP_GUARD_METRIC_SLOTS; index++) {
		const struct mcp_metric_value *slot = &slots[index];
		__u32 hook;
		__u32 layer;
		__u32 action;

		if (!slot->count)
			continue;
		decode_metric_index(index, &hook, &layer, &action);
		printf("  hook=%s layer=%s action=%s count=%llu avg_ns=%llu "
		       "min_ns=%llu max_ns=%llu buckets=[%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu]\n",
		       hook_name(hook), layer_name(layer), action_name(action),
		       (unsigned long long)slot->count,
		       (unsigned long long)(slot->total_ns / slot->count),
		       (unsigned long long)slot->min_ns,
		       (unsigned long long)slot->max_ns,
		       (unsigned long long)slot->buckets[0],
		       (unsigned long long)slot->buckets[1],
		       (unsigned long long)slot->buckets[2],
		       (unsigned long long)slot->buckets[3],
		       (unsigned long long)slot->buckets[4],
		       (unsigned long long)slot->buckets[5],
		       (unsigned long long)slot->buckets[6],
		       (unsigned long long)slot->buckets[7]);
	}
}

int main(void)
{
	struct naive_guard_bpf *skel;
	int err;

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	if (bump_memlock_rlimit() != 0)
		fprintf(stderr, "warning: failed to raise memlock rlimit: %s\n",
			strerror(errno));

	skel = naive_guard_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load naive eBPF LSM object\n");
		return 1;
	}

	err = configure_policy(bpf_map__fd(skel->maps.baseline_config_map));
	if (err) {
		fprintf(stderr, "failed to configure naive policy: %s\n",
			strerror(errno));
		naive_guard_bpf__destroy(skel);
		return 1;
	}

	err = naive_guard_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "failed to attach naive eBPF LSM programs: %d\n", err);
		naive_guard_bpf__destroy(skel);
		return 1;
	}

	printf("naive-ebpf-lsm running; send SIGINT to stop\n");
	fflush(stdout);

	while (!exiting)
		pause();

	print_metrics_summary(bpf_map__fd(skel->maps.metrics));
	naive_guard_bpf__destroy(skel);
	return 0;
}
