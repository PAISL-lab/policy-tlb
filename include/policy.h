#ifndef MCP_GUARD_POLICY_H
#define MCP_GUARD_POLICY_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#include "common.h"

struct mcp_policy_config {
	__u32 default_action;
	__u32 enforce;
	__u32 audit_allowed;
	__u32 rule_count;
};

struct mcp_policy_rule {
	__u32 enabled;
	__u32 rule_id;
	__u32 rule_type;
	__u32 action;
	__u32 hook_mask;
	__u32 flags;
	__u32 value_len;
	__u32 port;
	__u32 ipv4_addr;
	__u32 ipv4_mask;
	__u64 resource_id;
	char value[MCP_GUARD_RULE_VALUE_LEN];
	char name[MCP_GUARD_RULE_NAME_LEN];
};

#endif
