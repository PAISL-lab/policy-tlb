#ifndef MCP_GUARD_MAPS_BPF_H
#define MCP_GUARD_MAPS_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "../include/cache_key.h"
#include "../include/event.h"
#include "../include/policy.h"

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
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

#endif
