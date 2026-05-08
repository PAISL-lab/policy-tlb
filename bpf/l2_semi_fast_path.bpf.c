#ifndef MCP_GUARD_L2_SEMI_FAST_PATH_BPF_C
#define MCP_GUARD_L2_SEMI_FAST_PATH_BPF_C

#include "l1_fast_path.bpf.c"

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

	if (type != MCP_GUARD_S_IFREG && type != MCP_GUARD_S_IFDIR) {
		if (flags)
			*flags = 1;
		return MCP_GUARD_ACTION_ALLOW;
	}

	if (hook_id == MCP_GUARD_HOOK_FILE_READ && type == MCP_GUARD_S_IFDIR) {
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
