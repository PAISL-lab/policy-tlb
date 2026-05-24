// SPDX-License-Identifier: GPL-2.0-or-later
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "include/common.h"
#include "include/event.h"

#define BASELINE_PREFIX_LEN MCP_GUARD_RULE_VALUE_LEN

struct baseline_config {
	__u32 enforce;
	__u32 deny_port;
	char deny_exec_prefix[BASELINE_PREFIX_LEN];
	char deny_path_prefix[BASELINE_PREFIX_LEN];
};

struct baseline_scratch {
	char path[MCP_GUARD_PATH_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct baseline_config);
} baseline_config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MCP_GUARD_METRIC_SLOTS);
	__type(key, __u32);
	__type(value, struct mcp_metric_value);
} metrics SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct baseline_scratch);
} scratch SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

static __always_inline struct baseline_config *baseline_config(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&baseline_config_map, &key);
}

static __always_inline struct baseline_scratch *baseline_scratch(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&scratch, &key);
}

static __always_inline __u32 metric_index(__u32 hook_id, __u32 layer, __u32 action)
{
	return ((hook_id & 0x7) << 5) | ((layer & 0x7) << 2) | (action & 0x3);
}

static __always_inline __u32 hist_bucket(__u64 duration_ns)
{
	if (duration_ns < 100)
		return 0;
	if (duration_ns < 500)
		return 1;
	if (duration_ns < 1000)
		return 2;
	if (duration_ns < 5000)
		return 3;
	if (duration_ns < 10000)
		return 4;
	if (duration_ns < 50000)
		return 5;
	if (duration_ns < 100000)
		return 6;
	return 7;
}

static __always_inline void record_metric(__u32 hook_id, __u32 action, __u64 start_ns)
{
	__u64 duration_ns = bpf_ktime_get_ns() - start_ns;
	__u32 index = metric_index(hook_id, MCP_GUARD_LAYER_L3, action);
	__u32 bucket = hist_bucket(duration_ns);
	struct mcp_metric_value *metric;

	metric = bpf_map_lookup_elem(&metrics, &index);
	if (!metric)
		return;

	metric->count++;
	metric->total_ns += duration_ns;
	if (!metric->min_ns || duration_ns < metric->min_ns)
		metric->min_ns = duration_ns;
	if (duration_ns > metric->max_ns)
		metric->max_ns = duration_ns;
	metric->buckets[bucket]++;
}

static __always_inline int has_prefix(const char *value, const char *prefix)
{
	if (!prefix[0])
		return 0;

	for (__u32 i = 0; i < BASELINE_PREFIX_LEN; i++) {
		char want = prefix[i];
		char got = value[i];

		if (!want)
			return 1;
		if (got != want)
			return 0;
	}
	return 1;
}

static __always_inline int action_ret(struct baseline_config *cfg, __u32 action)
{
	if (action == MCP_GUARD_ACTION_DENY && (!cfg || cfg->enforce))
		return -MCP_GUARD_DENY_ERRNO;
	return 0;
}

static __always_inline int read_file_path(struct file *file, char *path)
{
	long ret;

	if (!file) {
		path[0] = 0;
		return -1;
	}

	ret = bpf_d_path(&file->f_path, path, MCP_GUARD_PATH_LEN);
	if (ret < 0) {
		path[0] = 0;
		return ret;
	}
	return 0;
}

static __always_inline __u64 file_resource_id(struct file *file)
{
	struct inode *inode;

	if (!file)
		return 0;

	inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return 0;

	return BPF_CORE_READ(inode, i_ino);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(naive_bprm_check_security, struct linux_binprm *bprm, int ret)
{
	struct baseline_config *cfg = baseline_config();
	struct baseline_scratch *tmp = baseline_scratch();
	const char *filename_ptr;
	__u64 start_ns = bpf_ktime_get_ns();
	__u32 action = MCP_GUARD_ACTION_ALLOW;

	if (ret)
		return ret;
	if (!tmp) {
		record_metric(MCP_GUARD_HOOK_EXEC, action, start_ns);
		return 0;
	}

	tmp->path[0] = 0;
	filename_ptr = BPF_CORE_READ(bprm, filename);
	if (filename_ptr)
		bpf_probe_read_kernel_str(tmp->path, MCP_GUARD_PATH_LEN, filename_ptr);

	if (cfg && has_prefix(tmp->path, cfg->deny_exec_prefix))
		action = MCP_GUARD_ACTION_DENY;

	record_metric(MCP_GUARD_HOOK_EXEC, action, start_ns);
	return action_ret(cfg, action);
}

SEC("lsm/file_open")
int BPF_PROG(naive_file_open, struct file *file, int ret)
{
	struct baseline_config *cfg = baseline_config();
	struct baseline_scratch *tmp = baseline_scratch();
	__u64 start_ns = bpf_ktime_get_ns();
	__u32 action = MCP_GUARD_ACTION_ALLOW;

	if (ret)
		return ret;
	if (tmp && read_file_path(file, tmp->path) == 0 &&
	    cfg && has_prefix(tmp->path, cfg->deny_path_prefix))
		action = MCP_GUARD_ACTION_DENY;

	record_metric(MCP_GUARD_HOOK_FILE_OPEN, action, start_ns);
	return action_ret(cfg, action);
}

SEC("lsm/file_permission")
int BPF_PROG(naive_file_permission, struct file *file, int mask, int ret)
{
	struct baseline_config *cfg = baseline_config();
	__u64 start_ns = bpf_ktime_get_ns();
	__u64 resource_id;
	__u32 hook_id = MCP_GUARD_HOOK_FILE_READ;
	__u32 action = MCP_GUARD_ACTION_ALLOW;

	if (ret)
		return ret;
	if (mask & (MCP_GUARD_MAY_WRITE | MCP_GUARD_MAY_APPEND))
		hook_id = MCP_GUARD_HOOK_FILE_WRITE;
	else if (!(mask & MCP_GUARD_MAY_READ))
		return 0;

	/*
	 * bpf_d_path() is not available from this LSM hook on all target
	 * kernels. The naive baseline still performs per-event kernel work and
	 * policy accounting here, but path-prefix deny decisions are made at
	 * file_open where path extraction is verifier-accepted.
	 */
	resource_id = file_resource_id(file);
	if (!resource_id && cfg && cfg->deny_path_prefix[0])
		action = MCP_GUARD_ACTION_ALLOW;

	record_metric(hook_id, action, start_ns);
	return action_ret(cfg, action);
}

SEC("lsm/socket_connect")
int BPF_PROG(naive_socket_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen, int ret)
{
	struct baseline_config *cfg = baseline_config();
	struct sockaddr_in addr4 = {};
	__u64 start_ns = bpf_ktime_get_ns();
	__u16 family = 0;
	__u16 port = 0;
	__u32 action = MCP_GUARD_ACTION_ALLOW;

	(void)sock;
	(void)addrlen;
	if (ret)
		return ret;
	if (address) {
		bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);
		if (family == MCP_GUARD_AF_INET) {
			bpf_probe_read_kernel(&addr4, sizeof(addr4), address);
			port = bpf_ntohs(addr4.sin_port);
			if (cfg && cfg->deny_port && port == cfg->deny_port)
				action = MCP_GUARD_ACTION_DENY;
		}
	}

	record_metric(MCP_GUARD_HOOK_SOCKET_CONNECT, action, start_ns);
	return action_ret(cfg, action);
}
