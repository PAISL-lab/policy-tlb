#include "bpf_loader.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/libbpf.h>

#include "mcp_guard.skel.h"

struct mcp_bpf {
	struct mcp_guard_bpf *skel;
};

int mcp_bpf_open_load(struct mcp_bpf **out)
{
	struct mcp_bpf *guard;
	int err;

	if (!out)
		return -EINVAL;

	guard = calloc(1, sizeof(*guard));
	if (!guard)
		return -ENOMEM;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	guard->skel = mcp_guard_bpf__open();
	if (!guard->skel) {
		err = -errno;
		fprintf(stderr, "failed to open BPF skeleton: %s\n", strerror(errno));
		free(guard);
		return err;
	}

	err = mcp_guard_bpf__load(guard->skel);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		mcp_bpf_destroy(guard);
		return err;
	}

	*out = guard;
	return 0;
}

int mcp_bpf_attach(struct mcp_bpf *guard)
{
	int err;

	if (!guard || !guard->skel)
		return -EINVAL;

	err = mcp_guard_bpf__attach(guard->skel);
	if (err)
		fprintf(stderr, "failed to attach BPF programs: %d\n", err);

	return err;
}

int mcp_bpf_map_fd(const struct mcp_bpf *guard, enum mcp_bpf_map_id id)
{
	if (!guard || !guard->skel)
		return -EINVAL;

	switch (id) {
	case MCP_BPF_MAP_L1_CACHE:
		return bpf_map__fd(guard->skel->maps.l1_cache);
	case MCP_BPF_MAP_GLOBAL_EPOCH:
		return bpf_map__fd(guard->skel->maps.global_epoch);
	case MCP_BPF_MAP_POLICY_CONFIG:
		return bpf_map__fd(guard->skel->maps.policy_config);
	case MCP_BPF_MAP_POLICY_RULES:
		return bpf_map__fd(guard->skel->maps.policy_rules);
	case MCP_BPF_MAP_EVENTS:
		return bpf_map__fd(guard->skel->maps.events);
	default:
		return -EINVAL;
	}
}

void mcp_bpf_destroy(struct mcp_bpf *guard)
{
	if (!guard)
		return;
	mcp_guard_bpf__destroy(guard->skel);
	free(guard);
}
