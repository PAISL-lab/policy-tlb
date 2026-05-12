#ifndef MCP_GUARD_L2_SEMI_FAST_PATH_BPF_C
#define MCP_GUARD_L2_SEMI_FAST_PATH_BPF_C

#include "l1_fast_path.bpf.c"

static __always_inline __u32 mcp_l2_policy_flags(void)
{
	__u32 key = MCP_GUARD_CONFIG_KEY;
	struct mcp_policy_config *cfg;

	cfg = bpf_map_lookup_elem(&policy_config, &key);
	if (!cfg)
		return MCP_GUARD_POLICY_F_SKIP_DIR_READ |
		       MCP_GUARD_POLICY_F_CACHE_FILE_FOLLOWUPS |
		       MCP_GUARD_POLICY_F_DENY_TAILCALL_FAIL;
	return cfg->flags;
}

static __always_inline int mcp_l2_file_decide(struct file *file,
					      __u32 hook_id,
					      __u32 *flags)
{
	struct inode *inode;
	__u16 mode;
	__u16 type;

	if (!file)
		return MCP_GUARD_ACTION_UNSET;

	inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return MCP_GUARD_ACTION_UNSET;

	mode = BPF_CORE_READ(inode, i_mode);
	type = mode & MCP_GUARD_S_IFMT;

	if (mcp_l2_policy_flags() & MCP_GUARD_POLICY_F_SKIP_L2_SAFE)
		return MCP_GUARD_ACTION_UNSET;

	if (type != MCP_GUARD_S_IFREG && type != MCP_GUARD_S_IFDIR) {
		if (flags)
			*flags = 1;
		return MCP_GUARD_ACTION_ALLOW;
	}

	if ((mcp_l2_policy_flags() & MCP_GUARD_POLICY_F_SKIP_DIR_READ) &&
	    hook_id == MCP_GUARD_HOOK_FILE_READ && type == MCP_GUARD_S_IFDIR) {
		if (flags)
			*flags = 2;
		return MCP_GUARD_ACTION_ALLOW;
	}

	return MCP_GUARD_ACTION_UNSET;
}

static __always_inline int mcp_l2_socket_decide(struct sockaddr *address,
						__u16 *family)
{
	__u16 addr_family = 0;

	if (!address)
		return MCP_GUARD_ACTION_UNSET;

	bpf_probe_read_kernel(&addr_family, sizeof(addr_family), &address->sa_family);
	if (family)
		*family = addr_family;

	if (addr_family != MCP_GUARD_AF_INET)
		return MCP_GUARD_ACTION_ALLOW;

	return MCP_GUARD_ACTION_UNSET;
}

static __always_inline int mcp_l2_exec_decide(const char *filename)
{
	if (!filename || !filename[0])
		return MCP_GUARD_ACTION_DENY;

	return MCP_GUARD_ACTION_UNSET;
}

#endif
