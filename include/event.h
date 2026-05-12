#ifndef MCP_GUARD_EVENT_H
#define MCP_GUARD_EVENT_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#include "common.h"

struct mcp_event {
	__u64 ts_ns;
	__u64 duration_ns;
	__u64 epoch;
	__u64 resource_id;
	__u32 tgid;
	__u32 pid;
	__u32 uid;
	__u32 gid;
	__u32 hook_id;
	__u32 action;
	__u32 layer;
	__u32 reason;
	__u32 rule_id;
	__u32 error;
	__u32 data_len;
	__u16 family;
	__u16 port;
	__u32 ipv4_addr;
	char comm[MCP_GUARD_COMM_LEN];
	char path[MCP_GUARD_PATH_LEN];
	char rule_name[MCP_GUARD_RULE_NAME_LEN];
};

struct mcp_metric_value {
	__u64 count;
	__u64 total_ns;
	__u64 min_ns;
	__u64 max_ns;
	__u64 buckets[MCP_GUARD_HIST_BUCKETS];
};

#endif
