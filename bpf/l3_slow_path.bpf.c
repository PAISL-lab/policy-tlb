#ifndef MCP_GUARD_L3_SLOW_PATH_BPF_C
#define MCP_GUARD_L3_SLOW_PATH_BPF_C

#include "l2_semi_fast_path.bpf.c"

static __always_inline struct mcp_policy_config *mcp_config(void)
{
	__u32 key = MCP_GUARD_CONFIG_KEY;

	return bpf_map_lookup_elem(&policy_config, &key);
}

static __always_inline int mcp_policy_default_action(void)
{
	struct mcp_policy_config *cfg = mcp_config();

	if (!cfg)
		return MCP_GUARD_ACTION_ALLOW;
	return cfg->default_action;
}

static __always_inline int mcp_policy_enforced(void)
{
	struct mcp_policy_config *cfg = mcp_config();

	if (!cfg)
		return 1;
	return cfg->enforce != 0;
}

static __always_inline int mcp_has_prefix(const char *value,
					  const char *prefix,
					  __u32 prefix_len)
{
	if (!prefix_len)
		return 0;

	for (__u32 i = 0; i < MCP_GUARD_RULE_VALUE_LEN; i++) {
		if (i >= prefix_len)
			return 1;
		if (!value[i])
			return 0;
		if (value[i] != prefix[i])
			return 0;
	}

	return 1;
}

static __always_inline void mcp_copy_rule_name(char *dst,
					       const struct mcp_policy_rule *rule)
{
	for (__u32 i = 0; i < MCP_GUARD_RULE_NAME_LEN; i++) {
		dst[i] = rule->name[i];
		if (!dst[i])
			break;
	}
}

static __always_inline int mcp_l3_string_decide(__u32 rule_type,
						__u32 hook_id,
						const char *value,
						__u64 resource_id,
						__u32 *rule_id,
						char *rule_name)
{
	__u32 hook_mask = mcp_guard_hook_mask(hook_id);

	for (__u32 i = 0; i < MCP_GUARD_MAX_RULES; i++) {
		struct mcp_policy_rule *rule = bpf_map_lookup_elem(&policy_rules, &i);

		if (!rule || !rule->enabled)
			continue;
		if (rule->rule_type != rule_type)
			continue;
		if (!(rule->hook_mask & hook_mask))
			continue;
		if (rule_type == MCP_GUARD_RULE_PATH_PREFIX &&
		    rule->resource_id && rule->resource_id == resource_id) {
			if (rule_id)
				*rule_id = rule->rule_id;
			if (rule_name)
				mcp_copy_rule_name(rule_name, rule);
			return rule->action;
		}
		if (!mcp_has_prefix(value, rule->value, rule->value_len))
			continue;

		if (rule_id)
			*rule_id = rule->rule_id;
		if (rule_name)
			mcp_copy_rule_name(rule_name, rule);
		return rule->action;
	}

	if (rule_id)
		*rule_id = 0;
	return mcp_policy_default_action();
}

static __always_inline int mcp_l3_resource_decide(__u32 rule_type,
						  __u32 hook_id,
						  __u64 resource_id,
						  __u32 *rule_id,
						  char *rule_name)
{
	__u32 hook_mask = mcp_guard_hook_mask(hook_id);

	for (__u32 i = 0; i < MCP_GUARD_MAX_RULES; i++) {
		struct mcp_policy_rule *rule = bpf_map_lookup_elem(&policy_rules, &i);

		if (!rule || !rule->enabled)
			continue;
		if (rule->rule_type != rule_type)
			continue;
		if (!(rule->hook_mask & hook_mask))
			continue;
		if (!rule->resource_id || rule->resource_id != resource_id)
			continue;

		if (rule_id)
			*rule_id = rule->rule_id;
		if (rule_name)
			mcp_copy_rule_name(rule_name, rule);
		return rule->action;
	}

	if (rule_id)
		*rule_id = 0;
	return mcp_policy_default_action();
}

static __always_inline int mcp_l3_ipv4_decide(__u32 ipv4_addr,
					      __u16 port,
					      __u32 *rule_id,
					      char *rule_name)
{
	__u32 hook_mask = mcp_guard_hook_mask(MCP_GUARD_HOOK_SOCKET_CONNECT);

	for (__u32 i = 0; i < MCP_GUARD_MAX_RULES; i++) {
		struct mcp_policy_rule *rule = bpf_map_lookup_elem(&policy_rules, &i);

		if (!rule || !rule->enabled)
			continue;
		if (rule->rule_type != MCP_GUARD_RULE_IPV4_CONNECT)
			continue;
		if (!(rule->hook_mask & hook_mask))
			continue;
		if (rule->port && rule->port != port)
			continue;
		if (rule->ipv4_mask && ((ipv4_addr ^ rule->ipv4_addr) & rule->ipv4_mask))
			continue;

		if (rule_id)
			*rule_id = rule->rule_id;
		if (rule_name)
			mcp_copy_rule_name(rule_name, rule);
		return rule->action;
	}

	if (rule_id)
		*rule_id = 0;
	return mcp_policy_default_action();
}

static __always_inline void mcp_copy_path(char *dst, const char *src)
{
	for (__u32 i = 0; i < MCP_GUARD_PATH_LEN; i++) {
		dst[i] = src[i];
		if (!dst[i])
			break;
	}
}

static __always_inline void mcp_copy_event_rule_name(char *dst, const char *src)
{
	for (__u32 i = 0; i < MCP_GUARD_RULE_NAME_LEN; i++) {
		dst[i] = src[i];
		if (!dst[i])
			break;
	}
}

static __always_inline void mcp_emit_event(__u32 hook_id,
					   __u32 action,
					   __u32 layer,
					   __u32 reason,
					   __u32 rule_id,
					   __u64 resource_id,
					   __u64 start_ns,
					   const char *path,
					   const char *rule_name,
					   __u16 family,
					   __u32 ipv4_addr,
					   __u16 port,
					   __u32 error)
{
	struct mcp_event *event;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();
	__u64 now_ns;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return;

	now_ns = bpf_ktime_get_ns();
	event->ts_ns = now_ns;
	event->duration_ns = now_ns - start_ns;
	event->epoch = mcp_current_epoch();
	event->resource_id = resource_id;
	event->tgid = (__u32)(pid_tgid >> 32);
	event->pid = (__u32)pid_tgid;
	event->uid = (__u32)uid_gid;
	event->gid = (__u32)(uid_gid >> 32);
	event->hook_id = hook_id;
	event->action = action;
	event->layer = layer;
	event->reason = reason;
	event->rule_id = rule_id;
	event->error = error;
	event->family = family;
	event->port = port;
	event->ipv4_addr = ipv4_addr;
	event->data_len = 0;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	if (path)
		mcp_copy_path(event->path, path);
	else
		event->path[0] = 0;

	if (rule_name)
		mcp_copy_event_rule_name(event->rule_name, rule_name);
	else
		event->rule_name[0] = 0;

	bpf_ringbuf_submit(event, 0);
}

#endif
