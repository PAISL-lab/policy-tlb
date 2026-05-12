#ifndef MCP_GUARD_POLICY_LOADER_H
#define MCP_GUARD_POLICY_LOADER_H

#include "../include/policy.h"

struct mcp_policy_load_result {
	__u32 rule_count;
	__u32 flags;
	__u32 active_generation;
	__u32 profile_id;
	__u32 agent_id;
	__u32 scope_mode;
	__u32 scope_count;
	__u64 epoch;
	char profile_name[MCP_GUARD_PROFILE_NAME_LEN];
};

int mcp_policy_load_dir(const char *policy_dir,
			int rules_fd,
			int path_trie_fd,
			int scope_comm_fd,
			int scope_pid_fd,
			int scope_tgid_fd,
			int config_fd,
			int epoch_fd,
			struct mcp_policy_load_result *result);

#endif
