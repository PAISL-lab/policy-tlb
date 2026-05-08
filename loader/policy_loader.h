#ifndef MCP_GUARD_POLICY_LOADER_H
#define MCP_GUARD_POLICY_LOADER_H

#include "../include/policy.h"

struct mcp_policy_load_result {
	__u32 rule_count;
	__u64 epoch;
};

int mcp_policy_load_dir(const char *policy_dir,
			int rules_fd,
			int config_fd,
			int epoch_fd,
			struct mcp_policy_load_result *result);

#endif
