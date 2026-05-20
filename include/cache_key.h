// SPDX-License-Identifier: Apache-2.0
#ifndef MCP_GUARD_CACHE_KEY_H
#define MCP_GUARD_CACHE_KEY_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

struct mcp_cache_key {
	__u32 tgid;
	__u32 pid;
	__u32 hook_id;
	__u32 reserved;
	__u64 resource_id;
};

struct mcp_cache_value {
	__u64 epoch;
	__u32 action;
	__u32 flags;
	__u32 rule_id;
	__u32 reason;
};

#endif
