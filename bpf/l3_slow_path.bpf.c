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
	if (!mcp_guard_action_valid(cfg->default_action))
		return MCP_GUARD_ACTION_DENY;
	return cfg->default_action;
}

static __always_inline int mcp_policy_enforced(void)
{
	struct mcp_policy_config *cfg = mcp_config();

	if (!cfg)
		return 1;
	return cfg->enforce != 0;
}

static __always_inline void mcp_current_profile(__u32 *profile_id,
						__u32 *agent_id)
{
	struct mcp_policy_config *cfg = mcp_config();

	if (!cfg) {
		if (profile_id)
			*profile_id = 0;
		if (agent_id)
			*agent_id = 0;
		return;
	}
	if (profile_id)
		*profile_id = cfg->profile_id;
	if (agent_id)
		*agent_id = cfg->agent_id;
}

static __always_inline int mcp_scope_matches(void)
{
	struct mcp_policy_config *cfg = mcp_config();
	struct mcp_scope_value *scope;
	struct mcp_comm_scope_key comm_key = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = (__u32)pid_tgid;
	__u32 tgid = (__u32)(pid_tgid >> 32);

	if (!cfg || cfg->scope_mode == MCP_GUARD_SCOPE_SYSTEM_WIDE)
		return 1;
	if (cfg->scope_mode != MCP_GUARD_SCOPE_SCOPED)
		return 0;

	scope = bpf_map_lookup_elem(&scope_pid, &pid);
	if (scope && scope->profile_id == cfg->profile_id &&
	    scope->agent_id == cfg->agent_id &&
	    scope->selector_type == MCP_GUARD_SCOPE_SELECTOR_PID)
		return 1;
	scope = bpf_map_lookup_elem(&scope_tgid, &tgid);
	if (scope && scope->profile_id == cfg->profile_id &&
	    scope->agent_id == cfg->agent_id &&
	    scope->selector_type == MCP_GUARD_SCOPE_SELECTOR_TGID)
		return 1;

	bpf_get_current_comm(&comm_key.comm, sizeof(comm_key.comm));
	scope = bpf_map_lookup_elem(&scope_comm, &comm_key);
	return scope && scope->profile_id == cfg->profile_id &&
	       scope->agent_id == cfg->agent_id &&
	       scope->selector_type == MCP_GUARD_SCOPE_SELECTOR_COMM;
}

static __always_inline __u32 mcp_metric_index(__u32 hook_id,
					      __u32 layer,
					      __u32 action)
{
	return ((hook_id & 0x7) << 5) | ((layer & 0x7) << 2) | (action & 0x3);
}

static __always_inline __u32 mcp_hist_bucket(__u64 duration_ns)
{
	if (duration_ns < 100)
		return 0;
	if (duration_ns < 500)
		return 1;
	if (duration_ns < 1000)
		return 2;
	if (duration_ns < 5000)
		return 3;
	if (duration_ns < 10000)
		return 4;
	if (duration_ns < 50000)
		return 5;
	if (duration_ns < 100000)
		return 6;
	return 7;
}

static __always_inline void mcp_record_metric(__u32 hook_id,
					      __u32 action,
					      __u32 layer,
					      __u64 start_ns)
{
	__u64 duration_ns = bpf_ktime_get_ns() - start_ns;
	__u32 index = mcp_metric_index(hook_id, layer, action);
	__u32 bucket = mcp_hist_bucket(duration_ns);
	struct mcp_metric_value *metric;

	metric = bpf_map_lookup_elem(&metrics, &index);
	if (!metric)
		return;

	metric->count++;
	metric->total_ns += duration_ns;
	if (!metric->min_ns || duration_ns < metric->min_ns)
		metric->min_ns = duration_ns;
	if (duration_ns > metric->max_ns)
		metric->max_ns = duration_ns;
	metric->buckets[bucket]++;
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

static __always_inline void mcp_copy_rule_name_from_path_value(
	char *dst, const struct mcp_path_policy_value *rule)
{
	for (__u32 i = 0; i < MCP_GUARD_RULE_NAME_LEN; i++) {
		dst[i] = rule->name[i];
		if (!dst[i])
			break;
	}
}

static __always_inline void mcp_copy_rule_name_from_indexed_value(
	char *dst, const struct mcp_indexed_policy_value *rule)
{
	for (__u32 i = 0; i < MCP_GUARD_RULE_NAME_LEN; i++) {
		dst[i] = rule->name[i];
		if (!dst[i])
			break;
	}
}

static __always_inline int mcp_l3_path_trie_decide(__u32 hook_id,
						   const char *path,
						   __u64 resource_id,
						   __u32 *rule_id,
						   char *rule_name)
{
	struct mcp_path_lpm_key key = {};
	struct mcp_path_policy_value *rule;
	struct mcp_policy_config *cfg = mcp_config();
	__u32 hook_mask = mcp_guard_hook_mask(hook_id);

	if (!path || !path[0])
		goto default_action;

	key.prefixlen = 32 + MCP_GUARD_PATH_LEN * 8;
	key.generation = cfg ? cfg->active_generation : 0;
	for (__u32 i = 0; i < MCP_GUARD_PATH_LEN; i++) {
		key.path[i] = path[i];
		if (!path[i])
			break;
	}

	rule = bpf_map_lookup_elem(&path_policy_trie, &key);
	if (!rule || !rule->enabled)
		goto default_action;
	if (!(rule->hook_mask & hook_mask))
		goto default_action;

	if (rule_id)
		*rule_id = rule->rule_id;
	if (rule_name)
		mcp_copy_rule_name_from_path_value(rule_name, rule);
	if (!mcp_guard_action_valid(rule->action))
		return MCP_GUARD_ACTION_DENY;
	return rule->action;

default_action:
	if (rule_id)
		*rule_id = 0;
	return mcp_policy_default_action();
}

static __always_inline int mcp_l3_command_trie_decide(__u32 hook_id,
						      const char *value,
						      __u32 *rule_id,
						      char *rule_name)
{
	struct mcp_command_lpm_key key = {};
	struct mcp_indexed_policy_value *rule;
	struct mcp_policy_config *cfg = mcp_config();
	__u32 hook_mask = mcp_guard_hook_mask(hook_id);

	if (!value || !value[0])
		goto default_action;

	key.prefixlen = 32 + MCP_GUARD_RULE_VALUE_LEN * 8;
	key.generation = cfg ? cfg->active_generation : 0;
	for (__u32 i = 0; i < MCP_GUARD_RULE_VALUE_LEN; i++) {
		key.command[i] = value[i];
		if (!value[i])
			break;
	}

	rule = bpf_map_lookup_elem(&command_policy_trie, &key);
	if (!rule || !rule->enabled)
		goto default_action;
	if (!(rule->hook_mask & hook_mask))
		goto default_action;

	if (rule_id)
		*rule_id = rule->rule_id;
	if (rule_name)
		mcp_copy_rule_name_from_indexed_value(rule_name, rule);
	if (!mcp_guard_action_valid(rule->action))
		return MCP_GUARD_ACTION_DENY;
	return rule->action;

default_action:
	if (rule_id)
		*rule_id = 0;
	return mcp_policy_default_action();
}

static __always_inline int mcp_l3_string_decide(__u32 rule_type,
						__u32 hook_id,
						const char *value,
						__u64 resource_id,
						__u32 *rule_id,
						char *rule_name)
{
	__u32 hook_mask = mcp_guard_hook_mask(hook_id);

	if (rule_type == MCP_GUARD_RULE_PATH_PREFIX)
		return mcp_l3_path_trie_decide(hook_id, value, resource_id,
					       rule_id, rule_name);
	if (rule_type == MCP_GUARD_RULE_COMMAND_PREFIX)
		return mcp_l3_command_trie_decide(hook_id, value, rule_id,
						  rule_name);

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
			if (!mcp_guard_action_valid(rule->action))
				return MCP_GUARD_ACTION_DENY;
			return rule->action;
		}
		if (!mcp_has_prefix(value, rule->value, rule->value_len))
			continue;

		if (rule_id)
			*rule_id = rule->rule_id;
		if (rule_name)
			mcp_copy_rule_name(rule_name, rule);
		if (!mcp_guard_action_valid(rule->action))
			return MCP_GUARD_ACTION_DENY;
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
	struct mcp_resource_policy_key key = {};
	struct mcp_indexed_policy_value *rule;
	struct mcp_policy_config *cfg = mcp_config();
	__u32 hook_mask = mcp_guard_hook_mask(hook_id);

	key.generation = cfg ? cfg->active_generation : 0;
	key.rule_type = rule_type;
	key.resource_id = resource_id;
	rule = bpf_map_lookup_elem(&resource_policy_hash, &key);
	if (rule && rule->enabled && (rule->hook_mask & hook_mask)) {
		if (rule_id)
			*rule_id = rule->rule_id;
		if (rule_name)
			mcp_copy_rule_name_from_indexed_value(rule_name, rule);
		if (!mcp_guard_action_valid(rule->action))
			return MCP_GUARD_ACTION_DENY;
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
	struct mcp_network_lpm_key key = {};
	struct mcp_indexed_policy_value *rule;
	struct mcp_policy_config *cfg = mcp_config();
	__u32 hook_mask = mcp_guard_hook_mask(MCP_GUARD_HOOK_SOCKET_CONNECT);

	key.prefixlen = 32 + 32 + 32;
	key.generation = cfg ? cfg->active_generation : 0;
	key.port = port;
	key.ipv4_addr = ipv4_addr;
	rule = bpf_map_lookup_elem(&network_policy_trie, &key);
	if (!rule) {
		key.port = 0;
		rule = bpf_map_lookup_elem(&network_policy_trie, &key);
	}
	if (rule && rule->enabled && (rule->hook_mask & hook_mask)) {
		if (rule_id)
			*rule_id = rule->rule_id;
		if (rule_name)
			mcp_copy_rule_name_from_indexed_value(rule_name, rule);
		if (!mcp_guard_action_valid(rule->action))
			return MCP_GUARD_ACTION_DENY;
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
	__builtin_memset(event, 0, sizeof(*event));

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
	mcp_current_profile(&event->profile_id, &event->agent_id);
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
