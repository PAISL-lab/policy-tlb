#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "l3_slow_path.bpf.c"

char LICENSE[] SEC("license") = "GPL";

static __always_inline int mcp_should_block(__u32 action)
{
	return action == MCP_GUARD_ACTION_DENY && mcp_policy_enforced();
}

static __always_inline int mcp_action_ret(__u32 action)
{
	if (mcp_should_block(action))
		return -MCP_GUARD_DENY_ERRNO;
	return 0;
}

static __always_inline int mcp_read_file_path(struct file *file, char *path)
{
	long ret;

	if (!file) {
		path[0] = 0;
		return -1;
	}

	ret = bpf_d_path(&file->f_path, path, MCP_GUARD_PATH_LEN);
	if (ret < 0) {
		path[0] = 0;
		return ret;
	}

	return 0;
}

static __always_inline void mcp_cache_file_followups(__u64 resource_id,
						     __u32 action,
						     __u32 rule_id,
						     __u32 reason)
{
	struct mcp_cache_key key = {};

	mcp_fill_cache_key(&key, MCP_GUARD_HOOK_FILE_READ, resource_id);
	mcp_l1_store(&key, action, 0, rule_id, reason);

	key.hook_id = MCP_GUARD_HOOK_FILE_WRITE;
	mcp_l1_store(&key, action, 0, rule_id, reason);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(mcp_guard_bprm_check_security, struct linux_binprm *bprm, int ret)
{
	char filename[MCP_GUARD_PATH_LEN] = {};
	char rule_name[MCP_GUARD_RULE_NAME_LEN] = {};
	struct mcp_cache_value cached = {};
	struct mcp_cache_key key = {};
	const char *filename_ptr;
	__u64 resource_id;
	__u64 start_ns = bpf_ktime_get_ns();
	__u32 layer = MCP_GUARD_LAYER_L3;
	__u32 rule_id = 0;
	__u32 reason = MCP_GUARD_REASON_DEFAULT;
	int action;

	if (ret)
		return ret;

	filename_ptr = BPF_CORE_READ(bprm, filename);
	if (filename_ptr)
		bpf_probe_read_kernel_str(filename, sizeof(filename), filename_ptr);

	resource_id = mcp_fnv1a_hash(filename, sizeof(filename));
	mcp_fill_cache_key(&key, MCP_GUARD_HOOK_EXEC, resource_id);

	action = mcp_l1_lookup(&key, &cached);
	if (action != MCP_GUARD_ACTION_UNSET) {
		if (action != MCP_GUARD_ACTION_ALLOW)
			mcp_emit_event(MCP_GUARD_HOOK_EXEC, action,
				       MCP_GUARD_LAYER_L1,
				       MCP_GUARD_REASON_L1_CACHE, cached.rule_id,
				       resource_id, start_ns, filename, 0, 0, 0, 0,
				       mcp_should_block(action) ? MCP_GUARD_DENY_ERRNO : 0);
		return mcp_action_ret(action);
	}

	action = mcp_l2_exec_decide(filename);
	if (action == MCP_GUARD_ACTION_UNSET) {
		action = mcp_l3_string_decide(MCP_GUARD_RULE_COMMAND_PREFIX,
					      MCP_GUARD_HOOK_EXEC, filename, 0,
					      &rule_id, rule_name);
		reason = rule_id ? MCP_GUARD_REASON_POLICY : MCP_GUARD_REASON_DEFAULT;
	} else {
		layer = MCP_GUARD_LAYER_L2;
		reason = MCP_GUARD_REASON_L2_SAFE;
	}

	mcp_l1_store(&key, action, 0, rule_id, reason);

	if (action != MCP_GUARD_ACTION_ALLOW)
		mcp_emit_event(MCP_GUARD_HOOK_EXEC, action, layer, reason, rule_id,
			       resource_id, start_ns, filename, rule_name, 0, 0, 0,
			       mcp_should_block(action) ? MCP_GUARD_DENY_ERRNO : 0);

	return mcp_action_ret(action);
}

SEC("lsm/file_open")
int BPF_PROG(mcp_guard_file_open, struct file *file, int ret)
{
	char path[MCP_GUARD_PATH_LEN] = {};
	char rule_name[MCP_GUARD_RULE_NAME_LEN] = {};
	struct mcp_cache_value cached = {};
	struct mcp_cache_key key = {};
	__u64 resource_id = mcp_file_resource_id(file);
	__u64 start_ns = bpf_ktime_get_ns();
	__u32 layer = MCP_GUARD_LAYER_L3;
	__u32 rule_id = 0;
	__u32 flags = 0;
	__u32 reason = MCP_GUARD_REASON_DEFAULT;
	int action;

	if (ret)
		return ret;

	mcp_fill_cache_key(&key, MCP_GUARD_HOOK_FILE_OPEN, resource_id);
	action = mcp_l1_lookup(&key, &cached);
	if (action != MCP_GUARD_ACTION_UNSET) {
		if (action != MCP_GUARD_ACTION_ALLOW)
			mcp_emit_event(MCP_GUARD_HOOK_FILE_OPEN, action,
				       MCP_GUARD_LAYER_L1,
				       MCP_GUARD_REASON_L1_CACHE, cached.rule_id,
				       resource_id, start_ns, 0, 0, 0, 0, 0,
				       mcp_should_block(action) ? MCP_GUARD_DENY_ERRNO : 0);
		return mcp_action_ret(action);
	}

	action = mcp_l2_file_decide(file, MCP_GUARD_HOOK_FILE_OPEN, &flags);
	if (action == MCP_GUARD_ACTION_UNSET) {
		mcp_read_file_path(file, path);
		action = mcp_l3_string_decide(MCP_GUARD_RULE_PATH_PREFIX,
					      MCP_GUARD_HOOK_FILE_OPEN, path, resource_id,
					      &rule_id, rule_name);
		reason = rule_id ? MCP_GUARD_REASON_POLICY : MCP_GUARD_REASON_DEFAULT;
	} else {
		layer = MCP_GUARD_LAYER_L2;
		reason = MCP_GUARD_REASON_L2_SAFE;
	}

	mcp_l1_store(&key, action, flags, rule_id, reason);
	mcp_cache_file_followups(resource_id, action, rule_id, reason);

	if (action != MCP_GUARD_ACTION_ALLOW)
		mcp_emit_event(MCP_GUARD_HOOK_FILE_OPEN, action, layer, reason, rule_id,
			       resource_id, start_ns, path, rule_name, 0, 0, 0,
			       mcp_should_block(action) ? MCP_GUARD_DENY_ERRNO : 0);

	return mcp_action_ret(action);
}

SEC("lsm/file_permission")
int BPF_PROG(mcp_guard_file_permission, struct file *file, int mask, int ret)
{
	char rule_name[MCP_GUARD_RULE_NAME_LEN] = {};
	struct mcp_cache_value cached = {};
	struct mcp_cache_key key = {};
	__u64 resource_id = mcp_file_resource_id(file);
	__u64 start_ns = bpf_ktime_get_ns();
	__u32 hook_id = MCP_GUARD_HOOK_FILE_READ;
	__u32 layer = MCP_GUARD_LAYER_L3;
	__u32 rule_id = 0;
	__u32 flags = 0;
	__u32 reason = MCP_GUARD_REASON_DEFAULT;
	int action;

	if (ret)
		return ret;

	if (mask & (MCP_GUARD_MAY_WRITE | MCP_GUARD_MAY_APPEND))
		hook_id = MCP_GUARD_HOOK_FILE_WRITE;

	mcp_fill_cache_key(&key, hook_id, resource_id);
	action = mcp_l1_lookup(&key, &cached);
	if (action != MCP_GUARD_ACTION_UNSET) {
		if (action != MCP_GUARD_ACTION_ALLOW)
			mcp_emit_event(hook_id, action, MCP_GUARD_LAYER_L1,
				       MCP_GUARD_REASON_L1_CACHE, cached.rule_id,
				       resource_id, start_ns, 0, 0, 0, 0, 0,
				       mcp_should_block(action) ? MCP_GUARD_DENY_ERRNO : 0);
		return mcp_action_ret(action);
	}

	action = mcp_l2_file_decide(file, hook_id, &flags);
	if (action == MCP_GUARD_ACTION_UNSET) {
		action = mcp_l3_resource_decide(MCP_GUARD_RULE_PATH_PREFIX,
						hook_id, resource_id,
						&rule_id, rule_name);
		reason = rule_id ? MCP_GUARD_REASON_POLICY : MCP_GUARD_REASON_DEFAULT;
	} else {
		layer = MCP_GUARD_LAYER_L2;
		reason = MCP_GUARD_REASON_L2_SAFE;
	}

	mcp_l1_store(&key, action, flags, rule_id, reason);

	if (action != MCP_GUARD_ACTION_ALLOW)
		mcp_emit_event(hook_id, action, layer, reason, rule_id, resource_id,
			       start_ns, 0, rule_name, 0, 0, 0,
			       mcp_should_block(action) ? MCP_GUARD_DENY_ERRNO : 0);

	return mcp_action_ret(action);
}

SEC("lsm/socket_connect")
int BPF_PROG(mcp_guard_socket_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen, int ret)
{
	char rule_name[MCP_GUARD_RULE_NAME_LEN] = {};
	struct mcp_cache_value cached = {};
	struct mcp_cache_key key = {};
	struct sockaddr_in addr4 = {};
	__u16 family = 0;
	__u16 port = 0;
	__u32 ipv4_addr = 0;
	__u64 resource_id = 0;
	__u64 start_ns = bpf_ktime_get_ns();
	__u32 layer = MCP_GUARD_LAYER_L3;
	__u32 rule_id = 0;
	__u32 reason = MCP_GUARD_REASON_DEFAULT;
	int action;

	(void)sock;
	(void)addrlen;

	if (ret)
		return ret;

	action = mcp_l2_socket_decide(address, &family);
	if (family == MCP_GUARD_AF_INET && address) {
		bpf_probe_read_kernel(&addr4, sizeof(addr4), address);
		ipv4_addr = addr4.sin_addr.s_addr;
		port = bpf_ntohs(addr4.sin_port);
		resource_id = ((__u64)ipv4_addr << 16) | port;
	}

	mcp_fill_cache_key(&key, MCP_GUARD_HOOK_SOCKET_CONNECT, resource_id);
	if (family == MCP_GUARD_AF_INET) {
		int cached_action = mcp_l1_lookup(&key, &cached);

		if (cached_action != MCP_GUARD_ACTION_UNSET) {
			if (cached_action != MCP_GUARD_ACTION_ALLOW)
				mcp_emit_event(MCP_GUARD_HOOK_SOCKET_CONNECT,
					       cached_action, MCP_GUARD_LAYER_L1,
					       MCP_GUARD_REASON_L1_CACHE,
					       cached.rule_id, resource_id, start_ns, 0, 0, family,
					       ipv4_addr, port,
					       mcp_should_block(cached_action) ?
					       MCP_GUARD_DENY_ERRNO : 0);
			return mcp_action_ret(cached_action);
		}
	}

	if (action == MCP_GUARD_ACTION_UNSET) {
		action = mcp_l3_ipv4_decide(ipv4_addr, port, &rule_id, rule_name);
		reason = rule_id ? MCP_GUARD_REASON_POLICY : MCP_GUARD_REASON_DEFAULT;
	} else {
		layer = MCP_GUARD_LAYER_L2;
		reason = MCP_GUARD_REASON_L2_SAFE;
	}

	mcp_l1_store(&key, action, 0, rule_id, reason);

	if (action != MCP_GUARD_ACTION_ALLOW)
		mcp_emit_event(MCP_GUARD_HOOK_SOCKET_CONNECT, action, layer, reason,
			       rule_id, resource_id, start_ns, 0, rule_name, family,
			       ipv4_addr, port,
			       mcp_should_block(action) ? MCP_GUARD_DENY_ERRNO : 0);

	return mcp_action_ret(action);
}
