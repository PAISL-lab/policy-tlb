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
	__u32 flags;
	__u32 active_generation;
	__u32 profile_id;
	__u32 agent_id;
	__u32 scope_mode;
	__u32 scope_count;
	char profile_name[MCP_GUARD_PROFILE_NAME_LEN];
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

struct mcp_path_lpm_key {
	__u32 prefixlen;
	__u32 generation;
	char path[MCP_GUARD_PATH_LEN];
};

struct mcp_path_policy_value {
	__u32 enabled;
	__u32 rule_id;
	__u32 action;
	__u32 hook_mask;
	__u32 flags;
	__u32 value_len;
	__u64 resource_id;
	char name[MCP_GUARD_RULE_NAME_LEN];
};

struct mcp_command_lpm_key {
	__u32 prefixlen;
	__u32 generation;
	char command[MCP_GUARD_RULE_VALUE_LEN];
};

struct mcp_network_lpm_key {
	__u32 prefixlen;
	__u32 generation;
	__u32 port;
	__u32 ipv4_addr;
};

struct mcp_resource_policy_key {
	__u32 generation;
	__u32 rule_type;
	__u64 resource_id;
};

struct mcp_indexed_policy_value {
	__u32 enabled;
	__u32 rule_id;
	__u32 action;
	__u32 hook_mask;
	__u32 flags;
	__u32 value_len;
	__u32 port;
	__u32 ipv4_addr;
	__u32 ipv4_mask;
	__u64 resource_id;
	char name[MCP_GUARD_RULE_NAME_LEN];
};

struct mcp_comm_scope_key {
	char comm[MCP_GUARD_COMM_LEN];
};

struct mcp_scope_value {
	__u32 profile_id;
	__u32 agent_id;
	__u32 selector_type;
};

#endif
