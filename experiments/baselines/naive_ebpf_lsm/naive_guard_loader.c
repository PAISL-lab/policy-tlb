// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/types.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include "include/common.h"
#include "include/event.h"
#include "include/policy.h"
#include "naive_guard.skel.h"

struct baseline_config {
	__u32 enforce;
	__u32 default_action;
	__u32 active_generation;
	__u32 reserved;
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

static __u64 path_resource_id(const char *value)
{
	struct stat st;

	if (!value || stat(value, &st) != 0)
		return 0;
	return (__u64)st.st_ino;
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

static __u32 path_prefix_bits(const char *path)
{
	return 32 + (__u32)strnlen(path, MCP_GUARD_PATH_LPM_LEN) * 8;
}

static __u32 command_prefix_bits(const char *command)
{
	return 32 + (__u32)strnlen(command, MCP_GUARD_RULE_VALUE_LEN) * 8;
}

static __u32 ipv4_prefix_bits(__u32 mask)
{
	__u32 host_mask = ntohl(mask);
	__u32 bits = 0;

	for (__u32 i = 0; i < 32; i++) {
		if (!(host_mask & (1U << (31 - i))))
			break;
		bits++;
	}
	return 32 + 32 + bits;
}

static int parse_ipv4_cidr(const char *value, __u32 *addr, __u32 *mask)
{
	char copy[64];
	char *slash;
	int prefix = 32;
	struct in_addr parsed;
	__u32 host_mask;

	if (!value || !addr || !mask)
		return -EINVAL;
	snprintf(copy, sizeof(copy), "%s", value);
	slash = strchr(copy, '/');
	if (slash) {
		*slash++ = 0;
		prefix = atoi(slash);
		if (prefix < 0 || prefix > 32)
			return -EINVAL;
	}

	if (inet_pton(AF_INET, copy, &parsed) != 1)
		return -EINVAL;

	host_mask = prefix == 0 ? 0 : 0xffffffffU << (32 - prefix);
	*addr = parsed.s_addr;
	*mask = htonl(host_mask);
	return 0;
}

static void fill_indexed_value(struct mcp_indexed_policy_value *value,
			       __u32 rule_id, __u32 rule_type, __u32 hook_mask,
			       __u32 action, const char *rule_value,
			       __u32 port, __u32 ipv4_addr, __u32 ipv4_mask,
			       __u64 resource_id)
{
	memset(value, 0, sizeof(*value));
	value->enabled = 1;
	value->rule_id = rule_id;
	value->action = action;
	value->hook_mask = hook_mask;
	value->value_len = rule_value ? strnlen(rule_value, MCP_GUARD_RULE_VALUE_LEN) : 0;
	value->port = port;
	value->ipv4_addr = ipv4_addr;
	value->ipv4_mask = ipv4_mask;
	value->resource_id = resource_id;
	snprintf(value->name, sizeof(value->name), "baseline-rule-%u", rule_id);
	(void)rule_type;
}

static int put_command_rule(int command_fd, __u32 rule_id, const char *command)
{
	struct mcp_command_lpm_key key = {};
	struct mcp_indexed_policy_value value = {};

	key.prefixlen = command_prefix_bits(command);
	key.generation = 1;
	snprintf(key.command, sizeof(key.command), "%s", command);
	fill_indexed_value(&value, rule_id, MCP_GUARD_RULE_COMMAND_PREFIX,
			   mcp_guard_hook_mask(MCP_GUARD_HOOK_EXEC),
			   MCP_GUARD_ACTION_DENY, command, 0, 0, 0, 0);
	if (bpf_map_update_elem(command_fd, &key, &value, BPF_ANY) != 0)
		return -errno;
	return 0;
}

static int put_path_rule(int path_fd, int resource_fd, __u32 rule_id,
			 const char *path)
{
	struct mcp_path_lpm_key path_key = {};
	struct mcp_path_policy_value path_value = {};
	__u64 resource_id = path_resource_id(path);
	__u32 hook_mask = mcp_guard_hook_mask(MCP_GUARD_HOOK_FILE_OPEN) |
			  mcp_guard_hook_mask(MCP_GUARD_HOOK_FILE_READ) |
			  mcp_guard_hook_mask(MCP_GUARD_HOOK_FILE_WRITE);

	path_key.prefixlen = path_prefix_bits(path);
	path_key.generation = 1;
	memcpy(path_key.path, path, strnlen(path, sizeof(path_key.path)));
	path_value.enabled = 1;
	path_value.rule_id = rule_id;
	path_value.action = MCP_GUARD_ACTION_DENY;
	path_value.hook_mask = hook_mask;
	path_value.value_len = strnlen(path, MCP_GUARD_RULE_VALUE_LEN);
	path_value.resource_id = resource_id;
	snprintf(path_value.name, sizeof(path_value.name), "baseline-rule-%u", rule_id);
	if (bpf_map_update_elem(path_fd, &path_key, &path_value, BPF_ANY) != 0)
		return -errno;

	if (resource_id) {
		struct mcp_resource_policy_key resource_key = {};
		struct mcp_indexed_policy_value resource_value = {};

		resource_key.generation = 1;
		resource_key.rule_type = MCP_GUARD_RULE_PATH_PREFIX;
		resource_key.resource_id = resource_id;
		fill_indexed_value(&resource_value, rule_id, MCP_GUARD_RULE_PATH_PREFIX,
				   hook_mask, MCP_GUARD_ACTION_DENY, path, 0,
				   0, 0, resource_id);
		if (bpf_map_update_elem(resource_fd, &resource_key, &resource_value,
					BPF_ANY) != 0)
			return -errno;
	}
	return 0;
}

static int put_network_rule(int network_fd, __u32 rule_id, const char *cidr,
			    __u32 port)
{
	struct mcp_network_lpm_key key = {};
	struct mcp_indexed_policy_value value = {};
	__u32 ipv4_addr = 0;
	__u32 ipv4_mask = 0;
	int err;

	err = parse_ipv4_cidr(cidr, &ipv4_addr, &ipv4_mask);
	if (err)
		return err;

	key.prefixlen = ipv4_prefix_bits(ipv4_mask);
	key.generation = 1;
	key.port = port;
	key.ipv4_addr = ipv4_addr;
	fill_indexed_value(&value, rule_id, MCP_GUARD_RULE_IPV4_CONNECT,
			   mcp_guard_hook_mask(MCP_GUARD_HOOK_SOCKET_CONNECT),
			   MCP_GUARD_ACTION_DENY, cidr, port, ipv4_addr,
			   ipv4_mask, 0);
	if (bpf_map_update_elem(network_fd, &key, &value, BPF_ANY) != 0)
		return -errno;
	return 0;
}

static int configure_policy(int config_fd, int path_fd, int command_fd,
			    int network_fd, int resource_fd)
{
	struct baseline_config cfg = {};
	__u32 key = 0;
	__u32 rule_id = 1;
	int err;

	cfg.enforce = env_u32("NAIVE_EBPF_ENFORCE", 1);
	cfg.default_action = MCP_GUARD_ACTION_ALLOW;
	cfg.active_generation = 1;

	err = put_command_rule(command_fd, rule_id++, "/usr/bin/curl");
	if (err)
		return err;
	err = put_command_rule(command_fd, rule_id++, "/usr/bin/wget");
	if (err)
		return err;
	err = put_command_rule(command_fd, rule_id++, "/usr/bin/nc");
	if (err)
		return err;
	err = put_path_rule(path_fd, resource_fd, rule_id++, "/etc/shadow");
	if (err)
		return err;
	err = put_path_rule(path_fd, resource_fd, rule_id++, "/root/");
	if (err)
		return err;
	err = put_path_rule(path_fd, resource_fd, rule_id++, "/home/demo/.ssh/");
	if (err)
		return err;
	err = put_network_rule(network_fd, rule_id++, "0.0.0.0/0",
			       env_u32("NAIVE_EBPF_DENY_PORT", 4444));
	if (err)
		return err;

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

	err = configure_policy(bpf_map__fd(skel->maps.baseline_config_map),
			       bpf_map__fd(skel->maps.baseline_path_policy_trie),
			       bpf_map__fd(skel->maps.baseline_command_policy_trie),
			       bpf_map__fd(skel->maps.baseline_network_policy_trie),
			       bpf_map__fd(skel->maps.baseline_resource_policy));
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
