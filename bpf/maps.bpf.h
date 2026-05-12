#ifndef MCP_GUARD_MAPS_BPF_H
#define MCP_GUARD_MAPS_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "../include/cache_key.h"
#include "../include/event.h"
#include "../include/policy.h"

struct mcp_tail_state {
	__u64 start_ns;
};

struct mcp_scratch {
	char path[MCP_GUARD_PATH_LEN];
	char rule_name[MCP_GUARD_RULE_NAME_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct mcp_cache_key);
	__type(value, struct mcp_cache_value);
} l1_cache SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} global_epoch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct mcp_policy_config);
} policy_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MCP_GUARD_MAX_RULES);
	__type(key, __u32);
	__type(value, struct mcp_policy_rule);
} policy_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, MCP_GUARD_MAX_RULES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct mcp_path_lpm_key);
	__type(value, struct mcp_path_policy_value);
} path_policy_trie SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

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
	__type(value, struct mcp_tail_state);
} tail_state SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct mcp_scratch);
} scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, MCP_GUARD_TAIL_MAX);
	__type(key, __u32);
	__type(value, __u32);
} exec_pipeline SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, MCP_GUARD_TAIL_MAX);
	__type(key, __u32);
	__type(value, __u32);
} file_open_pipeline SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, MCP_GUARD_TAIL_MAX);
	__type(key, __u32);
	__type(value, __u32);
} file_permission_pipeline SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, MCP_GUARD_TAIL_MAX);
	__type(key, __u32);
	__type(value, __u32);
} socket_connect_pipeline SEC(".maps");

#endif
