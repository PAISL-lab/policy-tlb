#ifndef MCP_GUARD_L1_FAST_PATH_BPF_C
#define MCP_GUARD_L1_FAST_PATH_BPF_C

#include "maps.bpf.h"

static __always_inline __u64 mcp_current_epoch(void)
{
	__u32 key = MCP_GUARD_EPOCH_KEY;
	__u64 *epoch = bpf_map_lookup_elem(&global_epoch, &key);

	if (!epoch)
		return 0;
	return *epoch;
}

static __always_inline void mcp_fill_cache_key(struct mcp_cache_key *key,
					       __u32 hook_id,
					       __u64 resource_id)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	key->pid = (__u32)pid_tgid;
	key->tgid = (__u32)(pid_tgid >> 32);
	key->hook_id = hook_id;
	key->reserved = 0;
	key->resource_id = resource_id;
}

static __always_inline int mcp_l1_lookup(const struct mcp_cache_key *key,
					 struct mcp_cache_value *out)
{
	struct mcp_cache_value *value;
	__u64 epoch = mcp_current_epoch();

	value = bpf_map_lookup_elem(&l1_cache, key);
	if (!value || value->epoch != epoch)
		return MCP_GUARD_ACTION_UNSET;

	if (out)
		*out = *value;
	return value->action;
}

static __always_inline void mcp_l1_store(const struct mcp_cache_key *key,
					 __u32 action,
					 __u32 flags,
					 __u32 rule_id,
					 __u32 reason)
{
	struct mcp_cache_value value = {};

	value.epoch = mcp_current_epoch();
	value.action = action;
	value.flags = flags;
	value.rule_id = rule_id;
	value.reason = reason;
	bpf_map_update_elem(&l1_cache, key, &value, BPF_ANY);
}

static __always_inline __u64 mcp_fnv1a_hash(const char *value, __u32 max_len)
{
	__u64 hash = 1469598103934665603ULL;

	for (__u32 i = 0; i < MCP_GUARD_PATH_LEN; i++) {
		if (i >= max_len)
			break;
		if (!value[i])
			break;
		hash ^= (__u8)value[i];
		hash *= 1099511628211ULL;
	}

	return hash ? hash : 1;
}

static __always_inline __u64 mcp_file_resource_id(struct file *file)
{
	struct inode *inode;
	__u64 ino = 0;

	if (!file)
		return 0;

	inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return 0;

	ino = BPF_CORE_READ(inode, i_ino);
	return ino;
}

#endif
