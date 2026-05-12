#ifndef MCP_GUARD_BPF_LOADER_H
#define MCP_GUARD_BPF_LOADER_H

struct mcp_bpf;

enum mcp_bpf_map_id {
	MCP_BPF_MAP_L1_CACHE = 1,
	MCP_BPF_MAP_GLOBAL_EPOCH,
	MCP_BPF_MAP_POLICY_CONFIG,
	MCP_BPF_MAP_POLICY_RULES,
	MCP_BPF_MAP_SCOPE_COMM,
	MCP_BPF_MAP_SCOPE_PID,
	MCP_BPF_MAP_SCOPE_TGID,
	MCP_BPF_MAP_PATH_POLICY_TRIE,
	MCP_BPF_MAP_METRICS,
	MCP_BPF_MAP_EVENTS,
};

int mcp_bpf_open_load(struct mcp_bpf **out);
int mcp_bpf_attach(struct mcp_bpf *guard);
int mcp_bpf_map_fd(const struct mcp_bpf *guard, enum mcp_bpf_map_id id);
void mcp_bpf_destroy(struct mcp_bpf *guard);

#endif
