#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "../include/common.h"
#include "bpf_loader.h"
#include "policy_loader.h"
#include "ringbuf_reader.h"
#include "unix_socket_server.h"

static volatile sig_atomic_t stop_requested;
static volatile sig_atomic_t reload_requested;

struct runtime_ctx {
	struct mcp_unix_socket_server *server;
};

struct cli_options {
	const char *policy_dir;
	unsigned int metrics_interval_sec;
};

struct metrics_snapshot {
	struct mcp_metric_value slots[MCP_GUARD_METRIC_SLOTS];
	__u64 total_count;
	__u64 l1_count;
	__u64 l2_count;
	__u64 l3_count;
};

static const char *hook_name(__u32 hook_id)
{
	switch (hook_id) {
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

static const char *action_name(__u32 action)
{
	switch (action) {
	case MCP_GUARD_ACTION_DENY:
		return "deny";
	case MCP_GUARD_ACTION_AUDIT:
		return "audit";
	case MCP_GUARD_ACTION_ALLOW:
		return "allow";
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

static double model_us_for_layer(__u32 layer)
{
	switch (layer) {
	case MCP_GUARD_LAYER_L1:
		return 0.018;
	case MCP_GUARD_LAYER_L2:
		return 0.023;
	case MCP_GUARD_LAYER_L3:
		return 0.989;
	default:
		return 0.0;
	}
}

static void print_policy_flags(__u32 flags)
{
	printf("policy flags: skip_dir_read=%u cache_file_followups=%u "
	       "deny_tailcall_fail=%u skip_l2_safe=%u\n",
	       !!(flags & MCP_GUARD_POLICY_F_SKIP_DIR_READ),
	       !!(flags & MCP_GUARD_POLICY_F_CACHE_FILE_FOLLOWUPS),
	       !!(flags & MCP_GUARD_POLICY_F_DENY_TAILCALL_FAIL),
	       !!(flags & MCP_GUARD_POLICY_F_SKIP_L2_SAFE));
}

static const char *scope_mode_name(__u32 mode)
{
	switch (mode) {
	case MCP_GUARD_SCOPE_SYSTEM_WIDE:
		return "system-wide";
	case MCP_GUARD_SCOPE_SCOPED:
		return "scoped";
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

static int read_metrics_snapshot(int metrics_fd, struct metrics_snapshot *snapshot)
{
	int cpus = libbpf_num_possible_cpus();
	size_t value_size;
	struct mcp_metric_value *values;

	if (metrics_fd < 0 || cpus <= 0)
		return -EINVAL;
	if (!snapshot)
		return -EINVAL;

	value_size = sizeof(*values) * (size_t)cpus;
	values = calloc(1, value_size);
	if (!values)
		return -ENOMEM;

	memset(snapshot, 0, sizeof(*snapshot));
	for (__u32 index = 0; index < MCP_GUARD_METRIC_SLOTS; index++) {
		__u32 hook;
		__u32 layer;
		__u32 action;

		if (bpf_map_lookup_elem(metrics_fd, &index, values) != 0)
			continue;

		for (int cpu = 0; cpu < cpus; cpu++) {
			struct mcp_metric_value *v = &values[cpu];
			struct mcp_metric_value *total = &snapshot->slots[index];

			total->count += v->count;
			total->total_ns += v->total_ns;
			if (v->min_ns && (!total->min_ns || v->min_ns < total->min_ns))
				total->min_ns = v->min_ns;
			if (v->max_ns > total->max_ns)
				total->max_ns = v->max_ns;
			for (__u32 b = 0; b < MCP_GUARD_HIST_BUCKETS; b++)
				total->buckets[b] += v->buckets[b];
		}

		if (!snapshot->slots[index].count)
			continue;

		decode_metric_index(index, &hook, &layer, &action);
		(void)hook;
		(void)action;
		snapshot->total_count += snapshot->slots[index].count;
		if (layer == MCP_GUARD_LAYER_L1)
			snapshot->l1_count += snapshot->slots[index].count;
		else if (layer == MCP_GUARD_LAYER_L2)
			snapshot->l2_count += snapshot->slots[index].count;
		else if (layer == MCP_GUARD_LAYER_L3)
			snapshot->l3_count += snapshot->slots[index].count;
	}

	free(values);
	return 0;
}

static void print_metrics_details(const struct metrics_snapshot *snapshot)
{
	if (!snapshot)
		return;

	for (__u32 index = 0; index < MCP_GUARD_METRIC_SLOTS; index++) {
		const struct mcp_metric_value *total = &snapshot->slots[index];
		__u32 hook;
		__u32 layer;
		__u32 action;

		if (!total->count)
			continue;

		decode_metric_index(index, &hook, &layer, &action);
		printf("  hook=%s layer=%s action=%s count=%llu avg_ns=%llu "
		       "min_ns=%llu max_ns=%llu buckets=[%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu]\n",
		       hook_name(hook), layer_name(layer), action_name(action),
		       (unsigned long long)total->count,
		       (unsigned long long)(total->total_ns / total->count),
		       (unsigned long long)total->min_ns,
		       (unsigned long long)total->max_ns,
		       (unsigned long long)total->buckets[0],
		       (unsigned long long)total->buckets[1],
		       (unsigned long long)total->buckets[2],
		       (unsigned long long)total->buckets[3],
		       (unsigned long long)total->buckets[4],
		       (unsigned long long)total->buckets[5],
		       (unsigned long long)total->buckets[6],
		       (unsigned long long)total->buckets[7]);
	}
}

static void print_metrics_ratios(const struct metrics_snapshot *snapshot)
{
	double l1 = 0.0;
	double l2 = 0.0;
	double l3 = 0.0;

	if (!snapshot || !snapshot->total_count)
		return;

	l1 = (double)snapshot->l1_count / (double)snapshot->total_count;
	l2 = (double)snapshot->l2_count / (double)snapshot->total_count;
	l3 = (double)snapshot->l3_count / (double)snapshot->total_count;
	printf("metrics ratios: total=%llu L1=%.6f L2=%.6f L3=%.6f\n",
	       (unsigned long long)snapshot->total_count, l1, l2, l3);
}

static void print_metrics_summary(int metrics_fd)
{
	struct metrics_snapshot snapshot;

	if (read_metrics_snapshot(metrics_fd, &snapshot) != 0)
		return;

	printf("metrics summary:\n");
	print_metrics_ratios(&snapshot);
	print_metrics_details(&snapshot);
}

static void publish_metrics_snapshot(int metrics_fd,
				     struct mcp_unix_socket_server *server,
				     int print_details)
{
	struct metrics_snapshot snapshot;

	if (read_metrics_snapshot(metrics_fd, &snapshot) != 0)
		return;

	printf("metrics snapshot:\n");
	print_metrics_ratios(&snapshot);
	if (print_details)
		print_metrics_details(&snapshot);

	if (server)
		mcp_unix_socket_server_publish_metrics(server,
						       snapshot.total_count,
						       snapshot.l1_count,
						       snapshot.l2_count,
						       snapshot.l3_count);
}

static void handle_signal(int signo)
{
	if (signo == SIGHUP)
		reload_requested = 1;
	else
		stop_requested = 1;
}

static int bump_memlock_rlimit(void)
{
	struct rlimit rlim = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim) != 0)
		return -errno;
	return 0;
}

static int parse_interval_seconds(const char *value, unsigned int *out)
{
	char *end;
	unsigned long seconds;

	if (!value || !out)
		return -EINVAL;

	errno = 0;
	seconds = strtoul(value, &end, 10);
	if (errno || end == value || seconds > 86400)
		return -EINVAL;
	if (*end == 's')
		end++;
	if (*end)
		return -EINVAL;

	*out = (unsigned int)seconds;
	return 0;
}

static int parse_args(int argc, char **argv, struct cli_options *options)
{
	if (!options)
		return -EINVAL;

	options->policy_dir = "policies";
	options->metrics_interval_sec = 0;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--metrics-interval") == 0) {
			if (++i >= argc)
				return -EINVAL;
			if (parse_interval_seconds(argv[i],
						   &options->metrics_interval_sec) != 0)
				return -EINVAL;
			continue;
		}
		if (strncmp(argv[i], "--metrics-interval=", 19) == 0) {
			if (parse_interval_seconds(argv[i] + 19,
						   &options->metrics_interval_sec) != 0)
				return -EINVAL;
			continue;
		}
		if (argv[i][0] == '-')
			return -EINVAL;
		options->policy_dir = argv[i];
	}

	return 0;
}

static __u64 monotonic_seconds(void)
{
	struct timespec ts = {};

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (__u64)ts.tv_sec;
}

static int print_event(void *ctx, const struct mcp_event *event)
{
	struct runtime_ctx *runtime = ctx;
	char addr[INET_ADDRSTRLEN] = "";

	if (event->family == MCP_GUARD_AF_INET && event->ipv4_addr) {
		struct in_addr in = {
			.s_addr = event->ipv4_addr,
		};

		inet_ntop(AF_INET, &in, addr, sizeof(addr));
	}

	double duration_us = (double)event->duration_ns / 1000.0;
	double model_us = model_us_for_layer(event->layer);

	printf("[%s] pid=%u uid=%u profile=%u agent=%u hook=%s layer=%s duration_ns=%llu "
	       "duration_us=%.3f model_us=%.3f delta_us=%.3f rule=%u error=%u path=%s",
	       action_name(event->action), event->pid, event->uid,
	       event->profile_id, event->agent_id,
	       hook_name(event->hook_id), layer_name(event->layer),
	       (unsigned long long)event->duration_ns, duration_us,
	       model_us, duration_us - model_us, event->rule_id, event->error,
	       event->path[0] ? event->path : "-");
	if (addr[0])
		printf(" dst=%s:%u", addr, event->port);
	if (event->rule_name[0])
		printf(" rule=%s", event->rule_name);
	printf("\n");

	if (runtime && runtime->server)
		mcp_unix_socket_server_publish(runtime->server, event);

	return 0;
}

static int load_policy_or_report(const char *policy_dir,
				 struct mcp_bpf *guard,
				 struct mcp_policy_load_result *result,
				 struct mcp_unix_socket_server *server)
{
	int err;

	err = mcp_policy_load_dir(policy_dir,
				  mcp_bpf_map_fd(guard, MCP_BPF_MAP_POLICY_RULES),
				  mcp_bpf_map_fd(guard, MCP_BPF_MAP_PATH_POLICY_TRIE),
				  mcp_bpf_map_fd(guard, MCP_BPF_MAP_COMMAND_POLICY_TRIE),
				  mcp_bpf_map_fd(guard, MCP_BPF_MAP_NETWORK_POLICY_TRIE),
				  mcp_bpf_map_fd(guard, MCP_BPF_MAP_RESOURCE_POLICY_HASH),
				  mcp_bpf_map_fd(guard, MCP_BPF_MAP_SCOPE_COMM),
				  mcp_bpf_map_fd(guard, MCP_BPF_MAP_SCOPE_PID),
				  mcp_bpf_map_fd(guard, MCP_BPF_MAP_SCOPE_TGID),
				  mcp_bpf_map_fd(guard, MCP_BPF_MAP_POLICY_CONFIG),
				  mcp_bpf_map_fd(guard, MCP_BPF_MAP_GLOBAL_EPOCH),
				  result);
	if (err) {
		fprintf(stderr, "failed to load policies from %s: %s\n",
			policy_dir, strerror(-err));
		if (server)
			mcp_unix_socket_server_publish_reload(server, 0,
							     result->rule_count,
							     result->active_generation,
							     result->epoch,
							     strerror(-err));
		return err;
	}

	printf("loaded %u policy rules, generation=%u epoch=%llu\n",
	       result->rule_count, result->active_generation,
	       (unsigned long long)result->epoch);
	printf("profile id=%u agent=%u mode=%s scopes=%u name=%s\n",
	       result->profile_id, result->agent_id,
	       scope_mode_name(result->scope_mode), result->scope_count,
	       result->profile_name[0] ? result->profile_name : "-");
	print_policy_flags(result->flags);
	if (server)
		mcp_unix_socket_server_publish_reload(server, 1,
						     result->rule_count,
						     result->active_generation,
						     result->epoch, "");
	return 0;
}

int main(int argc, char **argv)
{
	struct cli_options options;
	struct mcp_policy_load_result policy_result = {};
	struct mcp_ringbuf_reader *reader = NULL;
	struct runtime_ctx runtime = {};
	struct mcp_bpf *guard = NULL;
	__u64 next_metrics_ts = 0;
	int err;

	setvbuf(stdout, NULL, _IOLBF, 0);
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
	signal(SIGHUP, handle_signal);

	err = parse_args(argc, argv, &options);
	if (err) {
		fprintf(stderr,
			"usage: %s [policy_dir] [--metrics-interval seconds]\n",
			argv[0]);
		goto out;
	}

	err = bump_memlock_rlimit();
	if (err)
		fprintf(stderr, "warning: failed to raise memlock rlimit: %s\n",
			strerror(-err));

	err = mcp_bpf_open_load(&guard);
	if (err)
		goto out;

	err = load_policy_or_report(options.policy_dir, guard, &policy_result, NULL);
	if (err)
		goto out;

	err = mcp_bpf_attach(guard);
	if (err)
		goto out;

	err = mcp_unix_socket_server_start(MCP_GUARD_SOCKET_PATH, &runtime.server);
	if (err) {
		fprintf(stderr, "warning: unix socket disabled: %s\n", strerror(-err));
		err = 0;
	} else {
		printf("event socket listening at %s\n", MCP_GUARD_SOCKET_PATH);
	}

	err = mcp_ringbuf_reader_open(mcp_bpf_map_fd(guard, MCP_BPF_MAP_EVENTS),
				      print_event, &runtime, &reader);
	if (err) {
		fprintf(stderr, "failed to open ring buffer: %s\n", strerror(-err));
		goto out;
	}

	printf("mcp-guard running; send SIGHUP to reload policy, Ctrl-C to stop\n");
	if (options.metrics_interval_sec)
		next_metrics_ts = monotonic_seconds() + options.metrics_interval_sec;

	while (!stop_requested) {
		if (reload_requested) {
			reload_requested = 0;
			load_policy_or_report(options.policy_dir, guard,
					      &policy_result, runtime.server);
		}

		if (runtime.server)
			mcp_unix_socket_server_accept(runtime.server);

		if (options.metrics_interval_sec &&
		    monotonic_seconds() >= next_metrics_ts) {
			publish_metrics_snapshot(mcp_bpf_map_fd(guard, MCP_BPF_MAP_METRICS),
						 runtime.server, 0);
			next_metrics_ts = monotonic_seconds() +
					  options.metrics_interval_sec;
		}

		err = mcp_ringbuf_reader_poll(reader, 250);
		if (err == -EINTR) {
			err = 0;
			continue;
		}
		if (err < 0) {
			fprintf(stderr, "ring buffer poll failed: %s\n", strerror(-err));
			break;
		}
		err = 0;
	}

out:
	if (guard)
		print_metrics_summary(mcp_bpf_map_fd(guard, MCP_BPF_MAP_METRICS));
	mcp_ringbuf_reader_close(reader);
	mcp_unix_socket_server_stop(runtime.server);
	mcp_bpf_destroy(guard);
	return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
