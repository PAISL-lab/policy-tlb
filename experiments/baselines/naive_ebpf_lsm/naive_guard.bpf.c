// SPDX-License-Identifier: GPL-2.0-or-later
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "include/common.h"
#include "include/event.h"
#include "include/policy.h"

struct baseline_config {
	__u32 enforce;
	__u32 default_action;
	__u32 active_generation;
	__u32 reserved;
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
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, MCP_GUARD_MAX_RULES * 2);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct mcp_path_lpm_key);
	__type(value, struct mcp_path_policy_value);
} baseline_path_policy_trie SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, MCP_GUARD_MAX_RULES * 2);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct mcp_command_lpm_key);
	__type(value, struct mcp_indexed_policy_value);
} baseline_command_policy_trie SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, MCP_GUARD_MAX_RULES * 2);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct mcp_network_lpm_key);
	__type(value, struct mcp_indexed_policy_value);
} baseline_network_policy_trie SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MCP_GUARD_MAX_RULES * 2);
	__type(key, struct mcp_resource_policy_key);
	__type(value, struct mcp_indexed_policy_value);
} baseline_resource_policy SEC(".maps");

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

static __always_inline int baseline_action_valid(__u32 action)
{
	return action == MCP_GUARD_ACTION_ALLOW ||
	       action == MCP_GUARD_ACTION_DENY ||
	       action == MCP_GUARD_ACTION_AUDIT;
}

static __always_inline __u32 baseline_default_action(struct baseline_config *cfg)
{
	if (!cfg || !baseline_action_valid(cfg->default_action))
		return MCP_GUARD_ACTION_ALLOW;
	return cfg->default_action;
}

static __always_inline __u32 baseline_generation(struct baseline_config *cfg)
{
	if (!cfg || !cfg->active_generation)
		return 1;
	return cfg->active_generation;
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

static __always_inline __u32 baseline_command_decide(struct baseline_config *cfg,
						     const char *value,
						     __u32 *rule_id)
{
	struct mcp_command_lpm_key key = {};
	struct mcp_indexed_policy_value *rule;
	__u32 hook_mask = mcp_guard_hook_mask(MCP_GUARD_HOOK_EXEC);

	if (rule_id)
		*rule_id = 0;
	if (!value || !value[0])
		return baseline_default_action(cfg);

	key.prefixlen = 32 + MCP_GUARD_RULE_VALUE_LEN * 8;
	key.generation = baseline_generation(cfg);
	for (__u32 i = 0; i < MCP_GUARD_RULE_VALUE_LEN; i++) {
		key.command[i] = value[i];
		if (!value[i])
			break;
	}

	rule = bpf_map_lookup_elem(&baseline_command_policy_trie, &key);
	if (rule && rule->enabled && (rule->hook_mask & hook_mask)) {
		if (rule_id)
			*rule_id = rule->rule_id;
		return baseline_action_valid(rule->action) ?
			rule->action : MCP_GUARD_ACTION_DENY;
	}

	return baseline_default_action(cfg);
}

static __always_inline __u32 baseline_path_decide(struct baseline_config *cfg,
						  __u32 hook_id,
						  const char *path,
						  __u64 resource_id,
						  __u32 *rule_id)
{
	struct mcp_path_lpm_key key = {};
	struct mcp_path_policy_value *rule;
	__u32 hook_mask = mcp_guard_hook_mask(hook_id);

	if (rule_id)
		*rule_id = 0;
	if (!path || !path[0])
		return baseline_default_action(cfg);

	key.prefixlen = 32 + MCP_GUARD_PATH_LPM_LEN * 8;
	key.generation = baseline_generation(cfg);
	for (__u32 i = 0; i < MCP_GUARD_PATH_LPM_LEN; i++) {
		key.path[i] = path[i];
		if (!path[i])
			break;
	}

	rule = bpf_map_lookup_elem(&baseline_path_policy_trie, &key);
	if (rule && rule->enabled && (rule->hook_mask & hook_mask)) {
		if (rule_id)
			*rule_id = rule->rule_id;
		return baseline_action_valid(rule->action) ?
			rule->action : MCP_GUARD_ACTION_DENY;
	}

	(void)resource_id;
	return baseline_default_action(cfg);
}

static __always_inline __u32 baseline_resource_decide(
	struct baseline_config *cfg, __u32 rule_type, __u32 hook_id,
	__u64 resource_id, __u32 *rule_id)
{
	struct mcp_resource_policy_key key = {};
	struct mcp_indexed_policy_value *rule;
	__u32 hook_mask = mcp_guard_hook_mask(hook_id);

	if (rule_id)
		*rule_id = 0;
	if (!resource_id)
		return baseline_default_action(cfg);

	key.generation = baseline_generation(cfg);
	key.rule_type = rule_type;
	key.resource_id = resource_id;
	rule = bpf_map_lookup_elem(&baseline_resource_policy, &key);
	if (rule && rule->enabled && (rule->hook_mask & hook_mask)) {
		if (rule_id)
			*rule_id = rule->rule_id;
		return baseline_action_valid(rule->action) ?
			rule->action : MCP_GUARD_ACTION_DENY;
	}

	return baseline_default_action(cfg);
}

static __always_inline __u32 baseline_network_decide(struct baseline_config *cfg,
						     __u32 ipv4_addr,
						     __u16 port,
						     __u32 *rule_id)
{
	struct mcp_network_lpm_key key = {};
	struct mcp_indexed_policy_value *rule;
	__u32 hook_mask = mcp_guard_hook_mask(MCP_GUARD_HOOK_SOCKET_CONNECT);

	if (rule_id)
		*rule_id = 0;

	key.prefixlen = 32 + 32 + 32;
	key.generation = baseline_generation(cfg);
	key.port = port;
	key.ipv4_addr = ipv4_addr;
	rule = bpf_map_lookup_elem(&baseline_network_policy_trie, &key);
	if (!rule) {
		key.port = 0;
		rule = bpf_map_lookup_elem(&baseline_network_policy_trie, &key);
	}

	if (rule && rule->enabled && (rule->hook_mask & hook_mask)) {
		if (rule_id)
			*rule_id = rule->rule_id;
		return baseline_action_valid(rule->action) ?
			rule->action : MCP_GUARD_ACTION_DENY;
	}

	return baseline_default_action(cfg);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(naive_bprm_check_security, struct linux_binprm *bprm, int ret)
{
	struct baseline_config *cfg = baseline_config();
	struct baseline_scratch *tmp = baseline_scratch();
	const char *filename_ptr;
	__u64 start_ns = bpf_ktime_get_ns();
	__u32 action = MCP_GUARD_ACTION_ALLOW;
	__u32 rule_id = 0;

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

	action = baseline_command_decide(cfg, tmp->path, &rule_id);

	record_metric(MCP_GUARD_HOOK_EXEC, action, start_ns);
	return action_ret(cfg, action);
}

SEC("lsm/file_open")
int BPF_PROG(naive_file_open, struct file *file, int ret)
{
	struct baseline_config *cfg = baseline_config();
	struct baseline_scratch *tmp = baseline_scratch();
	__u64 start_ns = bpf_ktime_get_ns();
	__u64 resource_id = file_resource_id(file);
	__u32 action = MCP_GUARD_ACTION_ALLOW;
	__u32 rule_id = 0;

	if (ret)
		return ret;
	if (tmp && read_file_path(file, tmp->path) == 0)
		action = baseline_path_decide(cfg, MCP_GUARD_HOOK_FILE_OPEN,
					      tmp->path, resource_id, &rule_id);
	else
		action = baseline_default_action(cfg);

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
	__u32 rule_id = 0;

	if (ret)
		return ret;
	if (mask & (MCP_GUARD_MAY_WRITE | MCP_GUARD_MAY_APPEND))
		hook_id = MCP_GUARD_HOOK_FILE_WRITE;
	else if (!(mask & MCP_GUARD_MAY_READ))
		return 0;

	resource_id = file_resource_id(file);
	action = baseline_resource_decide(cfg, MCP_GUARD_RULE_PATH_PREFIX,
					  hook_id, resource_id, &rule_id);

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
	__u32 ipv4_addr = 0;
	__u32 action = MCP_GUARD_ACTION_ALLOW;
	__u32 rule_id = 0;

	(void)sock;
	(void)addrlen;
	if (ret)
		return ret;
	if (address) {
		bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);
		if (family == MCP_GUARD_AF_INET) {
			bpf_probe_read_kernel(&addr4, sizeof(addr4), address);
			port = bpf_ntohs(addr4.sin_port);
			ipv4_addr = addr4.sin_addr.s_addr;
			action = baseline_network_decide(cfg, ipv4_addr, port,
							 &rule_id);
		}
	}

	record_metric(MCP_GUARD_HOOK_SOCKET_CONNECT, action, start_ns);
	return action_ret(cfg, action);
}
