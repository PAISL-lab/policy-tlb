#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "l3_slow_path.bpf.c"

char LICENSE[] SEC("license") = "GPL";

static __always_inline int mcp_should_block(__u32 action)
{
	if (!mcp_guard_action_valid(action))
		return 1;
	return action == MCP_GUARD_ACTION_DENY && mcp_policy_enforced();
}

static __always_inline int mcp_action_ret(__u32 action)
{
	if (!mcp_guard_action_valid(action))
		return -MCP_GUARD_DENY_ERRNO;
	if (mcp_should_block(action))
		return -MCP_GUARD_DENY_ERRNO;
	return 0;
}

static __always_inline int mcp_recorded_action_ret(__u32 hook_id,
						   __u32 action,
						   __u32 layer,
						   __u64 start_ns)
{
	mcp_record_metric(hook_id, action, layer, start_ns);
	return mcp_action_ret(action);
}

static __always_inline int mcp_tail_fail_ret(void)
{
	if (mcp_l2_policy_flags() & MCP_GUARD_POLICY_F_DENY_TAILCALL_FAIL)
		return -MCP_GUARD_DENY_ERRNO;
	return 0;
}

static __always_inline void mcp_set_tail_start(__u64 start_ns)
{
	__u32 key = 0;
	struct mcp_tail_state *state;

	state = bpf_map_lookup_elem(&tail_state, &key);
	if (state)
		state->start_ns = start_ns;
}

static __always_inline __u64 mcp_get_tail_start(void)
{
	__u32 key = 0;
	struct mcp_tail_state *state;

	state = bpf_map_lookup_elem(&tail_state, &key);
	if (!state || !state->start_ns)
		return bpf_ktime_get_ns();
	return state->start_ns;
}

static __always_inline struct mcp_scratch *mcp_get_scratch(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&scratch, &key);
}

static __always_inline void mcp_read_bprm_filename(struct linux_binprm *bprm,
						    char *filename)
{
	const char *filename_ptr;

	filename[0] = 0;
	filename_ptr = BPF_CORE_READ(bprm, filename);
	if (filename_ptr)
		bpf_probe_read_kernel_str(filename, MCP_GUARD_PATH_LEN, filename_ptr);
}

static __always_inline __u64 mcp_bprm_resource_id(struct linux_binprm *bprm,
						  const char *filename)
{
	struct file *file;
	__u64 resource_id;

	file = BPF_CORE_READ(bprm, file);
	resource_id = mcp_file_resource_id(file);
	if (resource_id)
		return resource_id;

	if (!filename)
		return 0;
	return mcp_fnv1a_hash(filename, MCP_GUARD_PATH_LEN);
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

static __always_inline __u64 mcp_socket_resource_id(struct sockaddr *address,
						    __u16 *family,
						    __u32 *ipv4_addr,
						    __u16 *port)
{
	struct sockaddr_in addr4 = {};
	__u16 addr_family = 0;

	if (family)
		*family = 0;
	if (ipv4_addr)
		*ipv4_addr = 0;
	if (port)
		*port = 0;

	if (!address)
		return 0;

	bpf_probe_read_kernel(&addr_family, sizeof(addr_family), &address->sa_family);
	if (family)
		*family = addr_family;

	if (addr_family != MCP_GUARD_AF_INET)
		return 0;

	bpf_probe_read_kernel(&addr4, sizeof(addr4), address);
	if (ipv4_addr)
		*ipv4_addr = addr4.sin_addr.s_addr;
	if (port)
		*port = bpf_ntohs(addr4.sin_port);

	return ((__u64)addr4.sin_addr.s_addr << 16) | bpf_ntohs(addr4.sin_port);
}

static __always_inline void mcp_cache_file_followups(__u64 resource_id,
						     __u32 action,
						     __u32 rule_id,
						     __u32 reason)
{
	struct mcp_cache_key key = {};

	if (!(mcp_l2_policy_flags() & MCP_GUARD_POLICY_F_CACHE_FILE_FOLLOWUPS))
		return;

	mcp_fill_cache_key(&key, MCP_GUARD_HOOK_FILE_READ, resource_id);
	mcp_l1_store(&key, action, 0, rule_id, reason);

	key.hook_id = MCP_GUARD_HOOK_FILE_WRITE;
	mcp_l1_store(&key, action, 0, rule_id, reason);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(mcp_guard_bprm_check_security, struct linux_binprm *bprm, int ret)
{
	struct mcp_scratch *scratch = mcp_get_scratch();
	struct mcp_cache_value cached = {};
	struct mcp_cache_key key = {};
	__u64 resource_id;
	__u64 start_ns = bpf_ktime_get_ns();
	int action;

	if (ret)
		return ret;
	if (!mcp_scope_matches())
		return 0;
	if (!scratch)
		return mcp_tail_fail_ret();

	mcp_set_tail_start(start_ns);
	mcp_read_bprm_filename(bprm, scratch->path);
	resource_id = mcp_bprm_resource_id(bprm, scratch->path);
	mcp_fill_cache_key(&key, MCP_GUARD_HOOK_EXEC, resource_id);

	action = mcp_l1_lookup(&key, &cached);
	if (action != MCP_GUARD_ACTION_UNSET) {
		if (action != MCP_GUARD_ACTION_ALLOW)
			mcp_emit_event(MCP_GUARD_HOOK_EXEC, action,
				       MCP_GUARD_LAYER_L1,
				       MCP_GUARD_REASON_L1_CACHE, cached.rule_id,
				       resource_id, start_ns, scratch->path, 0, 0, 0, 0,
				       mcp_should_block(action) ? MCP_GUARD_DENY_ERRNO : 0);
			return mcp_recorded_action_ret(MCP_GUARD_HOOK_EXEC, action,
						       MCP_GUARD_LAYER_L1,
						       start_ns);
	}

	bpf_tail_call(ctx, &exec_pipeline, MCP_GUARD_TAIL_L2);
	return mcp_tail_fail_ret();
}

SEC("lsm/bprm_check_security")
int BPF_PROG(mcp_guard_bprm_check_security_l2, struct linux_binprm *bprm, int ret)
{
	struct mcp_scratch *scratch = mcp_get_scratch();
	struct mcp_cache_key key = {};
	__u64 resource_id;
	__u64 start_ns = mcp_get_tail_start();
	int action;

	if (ret)
		return ret;
	if (!scratch)
		return mcp_tail_fail_ret();

	mcp_read_bprm_filename(bprm, scratch->path);
	resource_id = mcp_bprm_resource_id(bprm, scratch->path);

	action = mcp_l2_exec_decide(scratch->path);
	if (action == MCP_GUARD_ACTION_UNSET) {
		bpf_tail_call(ctx, &exec_pipeline, MCP_GUARD_TAIL_L3);
		return mcp_tail_fail_ret();
	}

	mcp_fill_cache_key(&key, MCP_GUARD_HOOK_EXEC, resource_id);
	mcp_l1_store(&key, action, 0, 0, MCP_GUARD_REASON_L2_SAFE);
	mcp_emit_event(MCP_GUARD_HOOK_EXEC, action, MCP_GUARD_LAYER_L2,
		       MCP_GUARD_REASON_L2_SAFE, 0, resource_id, start_ns,
		       scratch->path, 0, 0, 0, 0,
		       mcp_should_block(action) ? MCP_GUARD_DENY_ERRNO : 0);

	return mcp_recorded_action_ret(MCP_GUARD_HOOK_EXEC, action,
				       MCP_GUARD_LAYER_L2, start_ns);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(mcp_guard_bprm_check_security_l3, struct linux_binprm *bprm, int ret)
{
	struct mcp_scratch *scratch;
	struct mcp_cache_key key = {};
	__u64 resource_id = 0;
	__u64 start_ns = mcp_get_tail_start();
	__u32 rule_id = 0;
	__u32 reason = MCP_GUARD_REASON_DEFAULT;
	int action;

	if (ret)
		return ret;

	if (!mcp_policy_has_rules()) {
		action = mcp_policy_default_action();
		if (action == MCP_GUARD_ACTION_ALLOW) {
			resource_id = mcp_bprm_resource_id(bprm, 0);
			mcp_fill_cache_key(&key, MCP_GUARD_HOOK_EXEC, resource_id);
			mcp_l1_store(&key, action, 0, 0, reason);
			return mcp_recorded_action_ret(MCP_GUARD_HOOK_EXEC, action,
						       MCP_GUARD_LAYER_L3, start_ns);
		}
	}

	scratch = mcp_get_scratch();
	if (!scratch)
		return mcp_tail_fail_ret();

	scratch->rule_name[0] = 0;
	mcp_read_bprm_filename(bprm, scratch->path);
	resource_id = mcp_bprm_resource_id(bprm, scratch->path);
	action = mcp_l3_string_decide(MCP_GUARD_RULE_COMMAND_PREFIX,
				      MCP_GUARD_HOOK_EXEC, scratch->path, 0,
				      &rule_id, scratch->rule_name);
	reason = rule_id ? MCP_GUARD_REASON_POLICY : MCP_GUARD_REASON_DEFAULT;

	mcp_fill_cache_key(&key, MCP_GUARD_HOOK_EXEC, resource_id);
	mcp_l1_store(&key, action, 0, rule_id, reason);

	if (action != MCP_GUARD_ACTION_ALLOW)
		mcp_emit_event(MCP_GUARD_HOOK_EXEC, action, MCP_GUARD_LAYER_L3,
			       reason, rule_id, resource_id, start_ns,
			       scratch->path, scratch->rule_name, 0, 0, 0,
			       mcp_should_block(action) ? MCP_GUARD_DENY_ERRNO : 0);

	return mcp_recorded_action_ret(MCP_GUARD_HOOK_EXEC, action,
				       MCP_GUARD_LAYER_L3, start_ns);
}

SEC("lsm/file_open")
int BPF_PROG(mcp_guard_file_open, struct file *file, int ret)
{
	struct mcp_cache_value cached = {};
	struct mcp_cache_key key = {};
	__u64 resource_id = mcp_file_resource_id(file);
	__u64 start_ns = bpf_ktime_get_ns();
	int action;

	if (ret)
		return ret;
	if (!mcp_scope_matches())
		return 0;

	mcp_set_tail_start(start_ns);
	mcp_fill_cache_key(&key, MCP_GUARD_HOOK_FILE_OPEN, resource_id);
	action = mcp_l1_lookup(&key, &cached);
	if (action != MCP_GUARD_ACTION_UNSET) {
		if (action != MCP_GUARD_ACTION_ALLOW)
			mcp_emit_event(MCP_GUARD_HOOK_FILE_OPEN, action,
				       MCP_GUARD_LAYER_L1,
				       MCP_GUARD_REASON_L1_CACHE, cached.rule_id,
				       resource_id, start_ns, 0, 0, 0, 0, 0,
				       mcp_should_block(action) ? MCP_GUARD_DENY_ERRNO : 0);
			return mcp_recorded_action_ret(MCP_GUARD_HOOK_FILE_OPEN,
						       action, MCP_GUARD_LAYER_L1,
						       start_ns);
	}

	bpf_tail_call(ctx, &file_open_pipeline, MCP_GUARD_TAIL_L2);
	return mcp_tail_fail_ret();
}

SEC("lsm/file_open")
int BPF_PROG(mcp_guard_file_open_l2, struct file *file, int ret)
{
	struct mcp_cache_key key = {};
	__u64 resource_id = mcp_file_resource_id(file);
	__u64 start_ns = mcp_get_tail_start();
	__u32 flags = 0;
	int action;

	if (ret)
		return ret;

	action = mcp_l2_file_decide(file, MCP_GUARD_HOOK_FILE_OPEN, &flags);
	if (action == MCP_GUARD_ACTION_UNSET) {
		bpf_tail_call(ctx, &file_open_pipeline, MCP_GUARD_TAIL_L3);
		return mcp_tail_fail_ret();
	}

	mcp_fill_cache_key(&key, MCP_GUARD_HOOK_FILE_OPEN, resource_id);
	mcp_l1_store(&key, action, flags, 0, MCP_GUARD_REASON_L2_SAFE);
	mcp_cache_file_followups(resource_id, action, 0, MCP_GUARD_REASON_L2_SAFE);
	return mcp_recorded_action_ret(MCP_GUARD_HOOK_FILE_OPEN, action,
				       MCP_GUARD_LAYER_L2, start_ns);
}

SEC("lsm/file_open")
int BPF_PROG(mcp_guard_file_open_l3, struct file *file, int ret)
{
	struct mcp_scratch *scratch;
	struct mcp_cache_key key = {};
	__u64 resource_id = mcp_file_resource_id(file);
	__u64 start_ns = mcp_get_tail_start();
	__u32 rule_id = 0;
	__u32 reason = MCP_GUARD_REASON_DEFAULT;
	int action;

	if (ret)
		return ret;

	if (!mcp_policy_has_rules()) {
		action = mcp_policy_default_action();
		if (action == MCP_GUARD_ACTION_ALLOW) {
			mcp_fill_cache_key(&key, MCP_GUARD_HOOK_FILE_OPEN, resource_id);
			mcp_l1_store(&key, action, 0, 0, reason);
			mcp_cache_file_followups(resource_id, action, 0, reason);
			return mcp_recorded_action_ret(MCP_GUARD_HOOK_FILE_OPEN, action,
						       MCP_GUARD_LAYER_L3, start_ns);
		}
	}

	scratch = mcp_get_scratch();
	if (!scratch)
		return mcp_tail_fail_ret();

	scratch->rule_name[0] = 0;
	mcp_read_file_path(file, scratch->path);
	action = mcp_l3_string_decide(MCP_GUARD_RULE_PATH_PREFIX,
				      MCP_GUARD_HOOK_FILE_OPEN,
				      scratch->path, resource_id, &rule_id,
				      scratch->rule_name);
	reason = rule_id ? MCP_GUARD_REASON_POLICY : MCP_GUARD_REASON_DEFAULT;

	mcp_fill_cache_key(&key, MCP_GUARD_HOOK_FILE_OPEN, resource_id);
	mcp_l1_store(&key, action, 0, rule_id, reason);
	mcp_cache_file_followups(resource_id, action, rule_id, reason);

	if (action != MCP_GUARD_ACTION_ALLOW)
		mcp_emit_event(MCP_GUARD_HOOK_FILE_OPEN, action, MCP_GUARD_LAYER_L3,
			       reason, rule_id, resource_id, start_ns,
			       scratch->path, scratch->rule_name, 0, 0, 0,
			       mcp_should_block(action) ? MCP_GUARD_DENY_ERRNO : 0);

	return mcp_recorded_action_ret(MCP_GUARD_HOOK_FILE_OPEN, action,
				       MCP_GUARD_LAYER_L3, start_ns);
}

SEC("lsm/file_permission")
int BPF_PROG(mcp_guard_file_permission, struct file *file, int mask, int ret)
{
	struct mcp_cache_value cached = {};
	struct mcp_cache_key key = {};
	__u64 resource_id = mcp_file_resource_id(file);
	__u64 start_ns = bpf_ktime_get_ns();
	__u32 hook_id = MCP_GUARD_HOOK_FILE_READ;
	int action;

	if (ret)
		return ret;
	if (!mcp_scope_matches())
		return 0;

	mcp_set_tail_start(start_ns);
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
			return mcp_recorded_action_ret(hook_id, action,
						       MCP_GUARD_LAYER_L1,
						       start_ns);
	}

	bpf_tail_call(ctx, &file_permission_pipeline, MCP_GUARD_TAIL_L2);
	return mcp_tail_fail_ret();
}

SEC("lsm/file_permission")
int BPF_PROG(mcp_guard_file_permission_l2, struct file *file, int mask, int ret)
{
	struct mcp_cache_key key = {};
	__u64 resource_id = mcp_file_resource_id(file);
	__u64 start_ns = mcp_get_tail_start();
	__u32 hook_id = MCP_GUARD_HOOK_FILE_READ;
	__u32 flags = 0;
	int action;

	if (ret)
		return ret;

	if (mask & (MCP_GUARD_MAY_WRITE | MCP_GUARD_MAY_APPEND))
		hook_id = MCP_GUARD_HOOK_FILE_WRITE;

	action = mcp_l2_file_decide(file, hook_id, &flags);
	if (action == MCP_GUARD_ACTION_UNSET) {
		bpf_tail_call(ctx, &file_permission_pipeline, MCP_GUARD_TAIL_L3);
		return mcp_tail_fail_ret();
	}

	mcp_fill_cache_key(&key, hook_id, resource_id);
	mcp_l1_store(&key, action, flags, 0, MCP_GUARD_REASON_L2_SAFE);
	return mcp_recorded_action_ret(hook_id, action, MCP_GUARD_LAYER_L2,
				       start_ns);
}

SEC("lsm/file_permission")
int BPF_PROG(mcp_guard_file_permission_l3, struct file *file, int mask, int ret)
{
	struct mcp_scratch *scratch;
	struct mcp_cache_key key = {};
	__u64 resource_id = mcp_file_resource_id(file);
	__u64 start_ns = mcp_get_tail_start();
	__u32 hook_id = MCP_GUARD_HOOK_FILE_READ;
	__u32 rule_id = 0;
	__u32 reason = MCP_GUARD_REASON_DEFAULT;
	int action;

	if (ret)
		return ret;

	if (mask & (MCP_GUARD_MAY_WRITE | MCP_GUARD_MAY_APPEND))
		hook_id = MCP_GUARD_HOOK_FILE_WRITE;

	if (!mcp_policy_has_rules()) {
		action = mcp_policy_default_action();
		if (action == MCP_GUARD_ACTION_ALLOW) {
			mcp_fill_cache_key(&key, hook_id, resource_id);
			mcp_l1_store(&key, action, 0, 0, reason);
			return mcp_recorded_action_ret(hook_id, action,
						       MCP_GUARD_LAYER_L3, start_ns);
		}
	}

	scratch = mcp_get_scratch();
	if (!scratch)
		return mcp_tail_fail_ret();

	scratch->rule_name[0] = 0;
	action = mcp_l3_resource_decide(MCP_GUARD_RULE_PATH_PREFIX,
					hook_id, resource_id, &rule_id,
					scratch->rule_name);
	reason = rule_id ? MCP_GUARD_REASON_POLICY : MCP_GUARD_REASON_DEFAULT;

	mcp_fill_cache_key(&key, hook_id, resource_id);
	mcp_l1_store(&key, action, 0, rule_id, reason);

	if (action != MCP_GUARD_ACTION_ALLOW)
		mcp_emit_event(hook_id, action, MCP_GUARD_LAYER_L3,
			       reason, rule_id, resource_id, start_ns,
			       0, scratch->rule_name, 0, 0, 0,
			       mcp_should_block(action) ? MCP_GUARD_DENY_ERRNO : 0);

	return mcp_recorded_action_ret(hook_id, action, MCP_GUARD_LAYER_L3,
				       start_ns);
}

SEC("lsm/socket_connect")
int BPF_PROG(mcp_guard_socket_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen, int ret)
{
	struct mcp_cache_value cached = {};
	struct mcp_cache_key key = {};
	__u16 family = 0;
	__u16 port = 0;
	__u32 ipv4_addr = 0;
	__u64 resource_id;
	__u64 start_ns = bpf_ktime_get_ns();
	int action;

	(void)sock;
	(void)addrlen;

	if (ret)
		return ret;
	if (!mcp_scope_matches())
		return 0;

	mcp_set_tail_start(start_ns);
	resource_id = mcp_socket_resource_id(address, &family, &ipv4_addr, &port);
	if (family == MCP_GUARD_AF_INET) {
		mcp_fill_cache_key(&key, MCP_GUARD_HOOK_SOCKET_CONNECT, resource_id);
		action = mcp_l1_lookup(&key, &cached);
		if (action != MCP_GUARD_ACTION_UNSET) {
			if (action != MCP_GUARD_ACTION_ALLOW)
				mcp_emit_event(MCP_GUARD_HOOK_SOCKET_CONNECT,
					       action, MCP_GUARD_LAYER_L1,
					       MCP_GUARD_REASON_L1_CACHE,
					       cached.rule_id, resource_id, start_ns,
					       0, 0, family, ipv4_addr, port,
					       mcp_should_block(action) ?
					       MCP_GUARD_DENY_ERRNO : 0);
				return mcp_recorded_action_ret(
					MCP_GUARD_HOOK_SOCKET_CONNECT, action,
					MCP_GUARD_LAYER_L1, start_ns);
		}
	}

	bpf_tail_call(ctx, &socket_connect_pipeline, MCP_GUARD_TAIL_L2);
	return mcp_tail_fail_ret();
}

SEC("lsm/socket_connect")
int BPF_PROG(mcp_guard_socket_connect_l2, struct socket *sock, struct sockaddr *address,
	     int addrlen, int ret)
{
	__u16 family = 0;
	__u64 start_ns = mcp_get_tail_start();
	int action;

	(void)sock;
	(void)addrlen;

	if (ret)
		return ret;

	action = mcp_l2_socket_decide(address, &family);
	if (action == MCP_GUARD_ACTION_UNSET) {
		bpf_tail_call(ctx, &socket_connect_pipeline, MCP_GUARD_TAIL_L3);
		return mcp_tail_fail_ret();
	}

	return mcp_recorded_action_ret(MCP_GUARD_HOOK_SOCKET_CONNECT, action,
				       MCP_GUARD_LAYER_L2, start_ns);
}

SEC("lsm/socket_connect")
int BPF_PROG(mcp_guard_socket_connect_l3, struct socket *sock, struct sockaddr *address,
	     int addrlen, int ret)
{
	struct mcp_scratch *scratch;
	struct mcp_cache_key key = {};
	__u16 family = 0;
	__u16 port = 0;
	__u32 ipv4_addr = 0;
	__u64 resource_id;
	__u64 start_ns = mcp_get_tail_start();
	__u32 rule_id = 0;
	__u32 reason;
	int action;

	(void)sock;
	(void)addrlen;

	if (ret)
		return ret;

	if (!mcp_policy_has_rules()) {
		action = mcp_policy_default_action();
		if (action == MCP_GUARD_ACTION_ALLOW)
			return mcp_recorded_action_ret(
				MCP_GUARD_HOOK_SOCKET_CONNECT, action,
				MCP_GUARD_LAYER_L3, start_ns);
	}

	scratch = mcp_get_scratch();
	if (!scratch)
		return mcp_tail_fail_ret();

	scratch->rule_name[0] = 0;
	resource_id = mcp_socket_resource_id(address, &family, &ipv4_addr, &port);
	action = mcp_l3_ipv4_decide(ipv4_addr, port, &rule_id,
				    scratch->rule_name);
	reason = rule_id ? MCP_GUARD_REASON_POLICY : MCP_GUARD_REASON_DEFAULT;

	mcp_fill_cache_key(&key, MCP_GUARD_HOOK_SOCKET_CONNECT, resource_id);
	mcp_l1_store(&key, action, 0, rule_id, reason);

	if (action != MCP_GUARD_ACTION_ALLOW)
		mcp_emit_event(MCP_GUARD_HOOK_SOCKET_CONNECT, action,
			       MCP_GUARD_LAYER_L3, reason, rule_id, resource_id,
			       start_ns, 0, scratch->rule_name, family,
			       ipv4_addr, port,
			       mcp_should_block(action) ? MCP_GUARD_DENY_ERRNO : 0);

	return mcp_recorded_action_ret(MCP_GUARD_HOOK_SOCKET_CONNECT, action,
				       MCP_GUARD_LAYER_L3, start_ns);
}
