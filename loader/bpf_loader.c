#include "bpf_loader.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "common.h"
#include "mcp_guard.skel.h"

struct mcp_bpf {
	struct mcp_guard_bpf *skel;
};

static void mcp_disable_tail_autoattach(struct mcp_guard_bpf *skel)
{
	bpf_program__set_autoattach(skel->progs.mcp_guard_bprm_check_security_l2, false);
	bpf_program__set_autoattach(skel->progs.mcp_guard_bprm_check_security_l3, false);
	bpf_program__set_autoattach(skel->progs.mcp_guard_file_open_l2, false);
	bpf_program__set_autoattach(skel->progs.mcp_guard_file_open_l3, false);
	bpf_program__set_autoattach(skel->progs.mcp_guard_file_permission_l2, false);
	bpf_program__set_autoattach(skel->progs.mcp_guard_file_permission_l3, false);
	bpf_program__set_autoattach(skel->progs.mcp_guard_socket_connect_l2, false);
	bpf_program__set_autoattach(skel->progs.mcp_guard_socket_connect_l3, false);
}

static int mcp_update_tail_call(struct bpf_map *map, __u32 index,
				struct bpf_program *prog)
{
	int map_fd = bpf_map__fd(map);
	int prog_fd = bpf_program__fd(prog);

	if (map_fd < 0 || prog_fd < 0)
		return -EINVAL;

	if (bpf_map_update_elem(map_fd, &index, &prog_fd, BPF_ANY) != 0)
		return -errno;

	return 0;
}

static int mcp_populate_tail_calls(struct mcp_guard_bpf *skel)
{
	int err;

	err = mcp_update_tail_call(skel->maps.exec_pipeline,
				   MCP_GUARD_TAIL_L2,
				   skel->progs.mcp_guard_bprm_check_security_l2);
	if (err)
		return err;
	err = mcp_update_tail_call(skel->maps.exec_pipeline,
				   MCP_GUARD_TAIL_L3,
				   skel->progs.mcp_guard_bprm_check_security_l3);
	if (err)
		return err;

	err = mcp_update_tail_call(skel->maps.file_open_pipeline,
				   MCP_GUARD_TAIL_L2,
				   skel->progs.mcp_guard_file_open_l2);
	if (err)
		return err;
	err = mcp_update_tail_call(skel->maps.file_open_pipeline,
				   MCP_GUARD_TAIL_L3,
				   skel->progs.mcp_guard_file_open_l3);
	if (err)
		return err;

	err = mcp_update_tail_call(skel->maps.file_permission_pipeline,
				   MCP_GUARD_TAIL_L2,
				   skel->progs.mcp_guard_file_permission_l2);
	if (err)
		return err;
	err = mcp_update_tail_call(skel->maps.file_permission_pipeline,
				   MCP_GUARD_TAIL_L3,
				   skel->progs.mcp_guard_file_permission_l3);
	if (err)
		return err;

	err = mcp_update_tail_call(skel->maps.socket_connect_pipeline,
				   MCP_GUARD_TAIL_L2,
				   skel->progs.mcp_guard_socket_connect_l2);
	if (err)
		return err;
	err = mcp_update_tail_call(skel->maps.socket_connect_pipeline,
				   MCP_GUARD_TAIL_L3,
				   skel->progs.mcp_guard_socket_connect_l3);
	if (err)
		return err;

	return 0;
}

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
	mcp_disable_tail_autoattach(guard->skel);

	err = mcp_guard_bpf__load(guard->skel);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		mcp_bpf_destroy(guard);
		return err;
	}

	err = mcp_populate_tail_calls(guard->skel);
	if (err) {
		fprintf(stderr, "failed to populate BPF tail-call maps: %s\n",
			strerror(-err));
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
