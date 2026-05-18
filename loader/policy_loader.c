#include "policy_loader.h"

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "../include/common.h"

struct policy_load_state {
	struct mcp_policy_rule rules[MCP_GUARD_MAX_RULES];
	__u32 next_index;
};

struct scope_load_state {
	struct mcp_comm_scope_key comm_keys[MCP_GUARD_MAX_SCOPES];
	__u32 pid_keys[MCP_GUARD_MAX_SCOPES];
	__u32 tgid_keys[MCP_GUARD_MAX_SCOPES];
	__u32 comm_count;
	__u32 pid_count;
	__u32 tgid_count;
};

struct path_policy_entry {
	struct mcp_path_lpm_key key;
	struct mcp_path_policy_value value;
};

struct command_policy_entry {
	struct mcp_command_lpm_key key;
	struct mcp_indexed_policy_value value;
};

struct network_policy_entry {
	struct mcp_network_lpm_key key;
	struct mcp_indexed_policy_value value;
};

struct resource_policy_entry {
	struct mcp_resource_policy_key key;
	struct mcp_indexed_policy_value value;
};

struct comm_scope_entry {
	struct mcp_comm_scope_key key;
	struct mcp_scope_value value;
};

struct id_scope_entry {
	__u32 key;
	struct mcp_scope_value value;
};

struct policy_map_snapshot {
	struct mcp_policy_rule rules[MCP_GUARD_MAX_RULES];
	struct mcp_policy_config config;
	struct path_policy_entry path_entries[MCP_GUARD_MAX_RULES];
	struct command_policy_entry command_entries[MCP_GUARD_MAX_RULES];
	struct network_policy_entry network_entries[MCP_GUARD_MAX_RULES];
	struct resource_policy_entry resource_entries[MCP_GUARD_MAX_RULES];
	struct comm_scope_entry comm_entries[MCP_GUARD_MAX_SCOPES];
	struct id_scope_entry pid_entries[MCP_GUARD_MAX_SCOPES];
	struct id_scope_entry tgid_entries[MCP_GUARD_MAX_SCOPES];
	__u32 path_entry_count;
	__u32 command_entry_count;
	__u32 network_entry_count;
	__u32 resource_entry_count;
	__u32 comm_entry_count;
	__u32 pid_entry_count;
	__u32 tgid_entry_count;
	int have_config;
};

struct flag_spec {
	const char *name;
	__u32 value;
};

static const struct flag_spec config_flags[] = {
	{ "skip_dir_read", MCP_GUARD_POLICY_F_SKIP_DIR_READ },
	{ "cache_file_followups", MCP_GUARD_POLICY_F_CACHE_FILE_FOLLOWUPS },
	{ "deny_tailcall_fail", MCP_GUARD_POLICY_F_DENY_TAILCALL_FAIL },
	{ "skip_l2_safe", MCP_GUARD_POLICY_F_SKIP_L2_SAFE },
};

static const struct flag_spec rule_flags[] = {
	{ "skip_l2_safe", MCP_GUARD_RULE_F_SKIP_L2_SAFE },
};

static int read_text_file(const char *path, char **out)
{
	FILE *file;
	long size;
	char *buf;

	file = fopen(path, "rb");
	if (!file)
		return -errno;

	if (fseek(file, 0, SEEK_END) != 0) {
		int err = -errno;

		fclose(file);
		return err;
	}

	size = ftell(file);
	if (size < 0) {
		int err = -errno;

		fclose(file);
		return err;
	}
	rewind(file);

	buf = calloc(1, (size_t)size + 1);
	if (!buf) {
		fclose(file);
		return -ENOMEM;
	}

	if (size > 0 && fread(buf, 1, (size_t)size, file) != (size_t)size) {
		int err = ferror(file) ? -errno : -EIO;

		free(buf);
		fclose(file);
		return err;
	}

	fclose(file);
	*out = buf;
	return 0;
}

static char *json_field(char *obj, const char *key)
{
	char pattern[64];
	char *p;

	snprintf(pattern, sizeof(pattern), "\"%s\"", key);
	p = strstr(obj, pattern);
	if (!p)
		return NULL;

	p = strchr(p + strlen(pattern), ':');
	if (!p)
		return NULL;
	p++;
	while (*p && isspace((unsigned char)*p))
		p++;
	return p;
}

static int json_get_string(char *obj, const char *key, char *out, size_t out_len)
{
	char *p = json_field(obj, key);
	size_t i = 0;

	if (!p || *p != '"')
		return -ENOENT;
	p++;

	while (*p && *p != '"' && i + 1 < out_len) {
		if (*p == '\\' && p[1])
			p++;
		out[i++] = *p++;
	}
	out[i] = 0;
	return i ? 0 : -ENOENT;
}

static int json_get_u32(char *obj, const char *key, __u32 *out)
{
	char *p = json_field(obj, key);
	char *end;
	unsigned long value;

	if (!p)
		return -ENOENT;

	errno = 0;
	value = strtoul(p, &end, 0);
	if (errno || end == p || value > UINT_MAX)
		return -EINVAL;

	*out = (__u32)value;
	return 0;
}

static int json_get_u32_array(char *obj, const char *key,
			      __u32 *out, __u32 max_count, __u32 *count)
{
	char *p = json_field(obj, key);
	__u32 n = 0;

	if (count)
		*count = 0;
	if (!p)
		return 0;
	if (*p != '[')
		return -EINVAL;
	p++;

	while (*p) {
		char *end;
		unsigned long value;

		while (*p && (isspace((unsigned char)*p) || *p == ','))
			p++;
		if (*p == ']') {
			if (count)
				*count = n;
			return 0;
		}
		if (n >= max_count)
			return -ENOSPC;

		errno = 0;
		value = strtoul(p, &end, 0);
		if (errno || end == p || value > UINT_MAX)
			return -EINVAL;
		out[n++] = (__u32)value;
		p = end;
	}

	return -EINVAL;
}

static int json_get_string_array(char *obj, const char *key,
				 struct mcp_comm_scope_key *out,
				 __u32 max_count, __u32 *count)
{
	char *p = json_field(obj, key);
	__u32 n = 0;

	if (count)
		*count = 0;
	if (!p)
		return 0;
	if (*p != '[')
		return -EINVAL;
	p++;

	while (*p) {
		size_t i = 0;

		while (*p && (isspace((unsigned char)*p) || *p == ','))
			p++;
		if (*p == ']') {
			if (count)
				*count = n;
			return 0;
		}
		if (*p != '"' || n >= max_count)
			return -EINVAL;
		p++;

		memset(&out[n], 0, sizeof(out[n]));
		while (*p && *p != '"' && i + 1 < sizeof(out[n].comm)) {
			if (*p == '\\' && p[1])
				p++;
			out[n].comm[i++] = *p++;
		}
		if (*p != '"')
			return -EINVAL;
		p++;
		n++;
	}

	return -EINVAL;
}

static int json_get_bool(char *obj, const char *key, __u32 *out)
{
	char *p = json_field(obj, key);

	if (!p)
		return -ENOENT;
	if (strncmp(p, "true", 4) == 0) {
		*out = 1;
		return 0;
	}
	if (strncmp(p, "false", 5) == 0) {
		*out = 0;
		return 0;
	}
	return -EINVAL;
}

static void json_update_flag(char *obj, const char *key, __u32 flag, __u32 *flags)
{
	__u32 enabled;

	if (json_get_bool(obj, key, &enabled) != 0)
		return;
	if (enabled)
		*flags |= flag;
	else
		*flags &= ~flag;
}

static int flag_value_by_name(const struct flag_spec *specs, size_t spec_count,
			      const char *name, __u32 *value)
{
	for (size_t i = 0; i < spec_count; i++) {
		if (strcmp(specs[i].name, name) == 0) {
			*value = specs[i].value;
			return 0;
		}
	}
	return -ENOENT;
}

static int json_apply_flag_array(char *obj, const struct flag_spec *specs,
				 size_t spec_count, __u32 *flags)
{
	char *p = json_field(obj, "flags");

	if (!p)
		return 0;
	if (*p != '[')
		return -EINVAL;
	p++;

	while (*p) {
		char name[64] = {};
		size_t i = 0;
		__u32 flag = 0;

		while (*p && (isspace((unsigned char)*p) || *p == ','))
			p++;
		if (*p == ']')
			return 0;
		if (*p != '"')
			return -EINVAL;
		p++;

		while (*p && *p != '"' && i + 1 < sizeof(name)) {
			if (*p == '\\' && p[1])
				p++;
			name[i++] = *p++;
		}
		if (*p != '"')
			return -EINVAL;
		p++;

		if (flag_value_by_name(specs, spec_count, name, &flag) != 0) {
			fprintf(stderr, "unknown policy flag: %s\n", name);
			return -EINVAL;
		}
		*flags |= flag;
	}

	return -EINVAL;
}

static __u32 parse_action(const char *value)
{
	if (strcmp(value, "deny") == 0)
		return MCP_GUARD_ACTION_DENY;
	if (strcmp(value, "audit") == 0)
		return MCP_GUARD_ACTION_AUDIT;
	return MCP_GUARD_ACTION_ALLOW;
}

static __u32 default_hook_mask(__u32 rule_type)
{
	switch (rule_type) {
	case MCP_GUARD_RULE_COMMAND_PREFIX:
		return mcp_guard_hook_mask(MCP_GUARD_HOOK_EXEC);
	case MCP_GUARD_RULE_IPV4_CONNECT:
		return mcp_guard_hook_mask(MCP_GUARD_HOOK_SOCKET_CONNECT);
	case MCP_GUARD_RULE_PATH_PREFIX:
	default:
		return mcp_guard_hook_mask(MCP_GUARD_HOOK_FILE_OPEN) |
		       mcp_guard_hook_mask(MCP_GUARD_HOOK_FILE_READ) |
		       mcp_guard_hook_mask(MCP_GUARD_HOOK_FILE_WRITE);
	}
}

static int parse_ipv4_cidr(const char *value, __u32 *addr, __u32 *mask)
{
	char copy[64];
	char *slash;
	int prefix = 32;
	struct in_addr parsed;
	__u32 host_mask;

	if (!value || !addr || !mask)
		return -EINVAL;

	snprintf(copy, sizeof(copy), "%s", value);
	slash = strchr(copy, '/');
	if (slash) {
		*slash++ = 0;
		prefix = atoi(slash);
		if (prefix < 0 || prefix > 32)
			return -EINVAL;
	}

	if (inet_pton(AF_INET, copy, &parsed) != 1)
		return -EINVAL;

	if (prefix == 0)
		host_mask = 0;
	else
		host_mask = 0xffffffffU << (32 - prefix);

	*addr = parsed.s_addr;
	*mask = htonl(host_mask);
	return 0;
}

static __u64 path_resource_id(const char *value)
{
	struct stat st;

	if (!value || stat(value, &st) != 0)
		return 0;

	return (__u64)st.st_ino;
}

static int normalize_path_value(char *value)
{
	size_t len;

	if (!value)
		return -EINVAL;

	len = strnlen(value, MCP_GUARD_RULE_VALUE_LEN);
	if (!len)
		return -EINVAL;
	if (len >= MCP_GUARD_RULE_VALUE_LEN - 1)
		return -ENAMETOOLONG;
	if (value[0] != '/')
		return -EINVAL;

	while (len > 1 && value[len - 1] == '/') {
		value[len - 1] = 0;
		len--;
	}

	return 0;
}

static int add_rule(struct policy_load_state *state, struct mcp_policy_rule *rule)
{
	__u32 index;

	if (state->next_index >= MCP_GUARD_MAX_RULES)
		return -ENOSPC;

	index = state->next_index;
	rule->enabled = 1;
	rule->rule_id = index + 1;
	state->rules[index] = *rule;
	state->next_index++;
	return 0;
}

static int load_rule_file(const char *path, __u32 forced_type,
			  struct policy_load_state *state)
{
	char *buf;
	char *cursor;
	int err;

	err = read_text_file(path, &buf);
	if (err == -ENOENT)
		return 0;
	if (err)
		return err;

	cursor = buf;
	while ((cursor = strchr(cursor, '{')) != NULL) {
		struct mcp_policy_rule rule = {};
		char action[32] = "deny";
		char value[MCP_GUARD_RULE_VALUE_LEN] = {};
		char name[MCP_GUARD_RULE_NAME_LEN] = {};
		char *end = strchr(cursor, '}');
		char saved;
		__u32 port;

		if (!end)
			break;
		saved = *end;
		*end = 0;

		if (json_get_string(cursor, "value", value, sizeof(value)) != 0 &&
		    json_get_string(cursor, "cidr", value, sizeof(value)) != 0) {
			*end = saved;
			cursor = end + 1;
			continue;
		}

		json_get_string(cursor, "name", name, sizeof(name));
		json_get_string(cursor, "action", action, sizeof(action));
		err = json_apply_flag_array(cursor, rule_flags,
					    sizeof(rule_flags) / sizeof(rule_flags[0]),
					    &rule.flags);
		if (err) {
			*end = saved;
			free(buf);
			return err;
		}
		json_update_flag(cursor, "skip_l2_safe",
				 MCP_GUARD_RULE_F_SKIP_L2_SAFE, &rule.flags);

		rule.rule_type = forced_type;
		rule.action = parse_action(action);
		rule.hook_mask = default_hook_mask(rule.rule_type);
		if (rule.rule_type == MCP_GUARD_RULE_PATH_PREFIX) {
			err = normalize_path_value(value);
			if (err) {
				*end = saved;
				free(buf);
				return err;
			}
		}
		rule.value_len = strnlen(value, sizeof(rule.value));
		snprintf(rule.value, sizeof(rule.value), "%s", value);
		snprintf(rule.name, sizeof(rule.name), "%s", name[0] ? name : value);
		if (rule.rule_type == MCP_GUARD_RULE_PATH_PREFIX)
			rule.resource_id = path_resource_id(value);

		if (rule.rule_type == MCP_GUARD_RULE_IPV4_CONNECT) {
			if (parse_ipv4_cidr(value, &rule.ipv4_addr, &rule.ipv4_mask) != 0) {
				*end = saved;
				cursor = end + 1;
				continue;
			}
			if (json_get_u32(cursor, "port", &port) == 0)
				rule.port = port;
		}

		err = add_rule(state, &rule);
		*end = saved;
		if (err) {
			free(buf);
			return err;
		}
		cursor = end + 1;
	}

	free(buf);
	return 0;
}

static int load_config_file(const char *path, struct mcp_policy_config *config)
{
	char *buf;
	char action[32] = {};
	int err;

	err = read_text_file(path, &buf);
	if (err == -ENOENT)
		return 0;
	if (err)
		return err;

	if (json_get_string(buf, "default_action", action, sizeof(action)) == 0)
		config->default_action = parse_action(action);
	json_get_bool(buf, "enforce", &config->enforce);
	json_get_bool(buf, "audit_allowed", &config->audit_allowed);
	err = json_apply_flag_array(buf, config_flags,
				    sizeof(config_flags) / sizeof(config_flags[0]),
				    &config->flags);
	if (err) {
		free(buf);
		return err;
	}
	json_update_flag(buf, "skip_dir_read", MCP_GUARD_POLICY_F_SKIP_DIR_READ,
			 &config->flags);
	json_update_flag(buf, "cache_file_followups",
			 MCP_GUARD_POLICY_F_CACHE_FILE_FOLLOWUPS, &config->flags);
	json_update_flag(buf, "deny_tailcall_fail",
			 MCP_GUARD_POLICY_F_DENY_TAILCALL_FAIL, &config->flags);
	json_update_flag(buf, "skip_l2_safe",
			 MCP_GUARD_POLICY_F_SKIP_L2_SAFE, &config->flags);

	free(buf);
	return 0;
}

static int add_comm_scope(struct scope_load_state *scope, const char *comm)
{
	if (!scope || !comm || !comm[0])
		return -EINVAL;
	if (scope->comm_count >= MCP_GUARD_MAX_SCOPES)
		return -ENOSPC;

	memset(&scope->comm_keys[scope->comm_count], 0,
	       sizeof(scope->comm_keys[scope->comm_count]));
	snprintf(scope->comm_keys[scope->comm_count].comm,
		 sizeof(scope->comm_keys[scope->comm_count].comm), "%s", comm);
	scope->comm_count++;
	return 0;
}

static int add_id_scope(__u32 *keys, __u32 *count, __u32 id)
{
	if (!keys || !count || !id)
		return -EINVAL;
	if (*count >= MCP_GUARD_MAX_SCOPES)
		return -ENOSPC;

	keys[(*count)++] = id;
	return 0;
}

static int load_profile_file(const char *path, struct mcp_policy_config *config,
			     struct scope_load_state *scope)
{
	char *buf;
	char mode[32] = {};
	char profile[MCP_GUARD_PROFILE_NAME_LEN] = {};
	char comm[MCP_GUARD_COMM_LEN] = {};
	__u32 value = 0;
	__u32 added = 0;
	int err;

	err = read_text_file(path, &buf);
	if (err == -ENOENT)
		return 0;
	if (err)
		return err;

	if (json_get_string(buf, "profile", profile, sizeof(profile)) == 0)
		snprintf(config->profile_name, sizeof(config->profile_name), "%s",
			 profile);
	if (json_get_u32(buf, "profile_id", &value) == 0)
		config->profile_id = value;
	if (json_get_u32(buf, "agent_id", &value) == 0)
		config->agent_id = value;

	if (json_get_string(buf, "mode", mode, sizeof(mode)) == 0) {
		if (strcmp(mode, "system-wide") == 0 ||
		    strcmp(mode, "system_wide") == 0) {
			config->scope_mode = MCP_GUARD_SCOPE_SYSTEM_WIDE;
		} else if (strcmp(mode, "scoped") == 0 ||
			   strcmp(mode, "scope") == 0) {
			config->scope_mode = MCP_GUARD_SCOPE_SCOPED;
		} else {
			free(buf);
			return -EINVAL;
		}
	}

	if (json_get_string(buf, "comm", comm, sizeof(comm)) == 0) {
		err = add_comm_scope(scope, comm);
		if (err) {
			free(buf);
			return err;
		}
		added++;
	}
	err = json_get_string_array(buf, "comms",
				    &scope->comm_keys[scope->comm_count],
				    MCP_GUARD_MAX_SCOPES - scope->comm_count,
				    &added);
	if (err) {
		free(buf);
		return err;
	}
	scope->comm_count += added;

	if (json_get_u32(buf, "pid", &value) == 0) {
		err = add_id_scope(scope->pid_keys, &scope->pid_count, value);
		if (err) {
			free(buf);
			return err;
		}
	}
	added = 0;
	err = json_get_u32_array(buf, "pids",
				 &scope->pid_keys[scope->pid_count],
				 MCP_GUARD_MAX_SCOPES - scope->pid_count,
				 &added);
	if (err) {
		free(buf);
		return err;
	}
	scope->pid_count += added;

	if (json_get_u32(buf, "tgid", &value) == 0) {
		err = add_id_scope(scope->tgid_keys, &scope->tgid_count, value);
		if (err) {
			free(buf);
			return err;
		}
	}
	added = 0;
	err = json_get_u32_array(buf, "tgids",
				 &scope->tgid_keys[scope->tgid_count],
				 MCP_GUARD_MAX_SCOPES - scope->tgid_count,
				 &added);
	if (err) {
		free(buf);
		return err;
	}
	scope->tgid_count += added;

	config->scope_count = scope->comm_count + scope->pid_count +
			      scope->tgid_count;
	if (config->scope_mode == MCP_GUARD_SCOPE_SCOPED &&
	    !config->scope_count) {
		free(buf);
		return -EINVAL;
	}

	free(buf);
	return 0;
}

static int write_rules(int rules_fd, const struct policy_load_state *state)
{
	for (__u32 i = 0; i < MCP_GUARD_MAX_RULES; i++) {
		struct mcp_policy_rule rule = {};

		if (i < state->next_index)
			rule = state->rules[i];
		if (bpf_map_update_elem(rules_fd, &i, &rule, BPF_ANY) != 0)
			return -errno;
	}
	return 0;
}

static int snapshot_rules(int rules_fd, struct policy_map_snapshot *snapshot)
{
	if (rules_fd < 0 || !snapshot)
		return -EINVAL;

	for (__u32 i = 0; i < MCP_GUARD_MAX_RULES; i++) {
		struct mcp_policy_rule rule = {};

		if (bpf_map_lookup_elem(rules_fd, &i, &rule) != 0)
			memset(&rule, 0, sizeof(rule));
		snapshot->rules[i] = rule;
	}
	return 0;
}

static int snapshot_config(int config_fd, struct policy_map_snapshot *snapshot)
{
	__u32 key = MCP_GUARD_CONFIG_KEY;

	if (config_fd < 0 || !snapshot)
		return -EINVAL;

	if (bpf_map_lookup_elem(config_fd, &key, &snapshot->config) == 0) {
		snapshot->have_config = 1;
		return 0;
	}

	memset(&snapshot->config, 0, sizeof(snapshot->config));
	snapshot->have_config = 0;
	return 0;
}

static int snapshot_path_trie(int path_trie_fd, struct policy_map_snapshot *snapshot)
{
	struct mcp_path_lpm_key key = {};
	struct mcp_path_lpm_key next_key = {};
	int have_key = 0;

	if (path_trie_fd < 0 || !snapshot)
		return 0;

	snapshot->path_entry_count = 0;
	while (bpf_map_get_next_key(path_trie_fd, have_key ? &key : NULL,
				    &next_key) == 0) {
		struct path_policy_entry *entry;

		if (snapshot->path_entry_count >= MCP_GUARD_MAX_RULES)
			return -ENOSPC;

		entry = &snapshot->path_entries[snapshot->path_entry_count];
		entry->key = next_key;
		if (bpf_map_lookup_elem(path_trie_fd, &entry->key,
					&entry->value) != 0)
			return -errno;

		snapshot->path_entry_count++;
		key = next_key;
		have_key = 1;
	}

	return 0;
}

static int snapshot_command_trie(int fd, struct policy_map_snapshot *snapshot)
{
	struct mcp_command_lpm_key key = {};
	struct mcp_command_lpm_key next_key = {};
	int have_key = 0;

	if (fd < 0 || !snapshot)
		return 0;

	snapshot->command_entry_count = 0;
	while (bpf_map_get_next_key(fd, have_key ? &key : NULL, &next_key) == 0) {
		struct command_policy_entry *entry;

		if (snapshot->command_entry_count >= MCP_GUARD_MAX_RULES)
			return -ENOSPC;

		entry = &snapshot->command_entries[snapshot->command_entry_count];
		entry->key = next_key;
		if (bpf_map_lookup_elem(fd, &entry->key, &entry->value) != 0)
			return -errno;

		snapshot->command_entry_count++;
		key = next_key;
		have_key = 1;
	}

	return 0;
}

static int snapshot_network_trie(int fd, struct policy_map_snapshot *snapshot)
{
	struct mcp_network_lpm_key key = {};
	struct mcp_network_lpm_key next_key = {};
	int have_key = 0;

	if (fd < 0 || !snapshot)
		return 0;

	snapshot->network_entry_count = 0;
	while (bpf_map_get_next_key(fd, have_key ? &key : NULL, &next_key) == 0) {
		struct network_policy_entry *entry;

		if (snapshot->network_entry_count >= MCP_GUARD_MAX_RULES)
			return -ENOSPC;

		entry = &snapshot->network_entries[snapshot->network_entry_count];
		entry->key = next_key;
		if (bpf_map_lookup_elem(fd, &entry->key, &entry->value) != 0)
			return -errno;

		snapshot->network_entry_count++;
		key = next_key;
		have_key = 1;
	}

	return 0;
}

static int snapshot_resource_hash(int fd, struct policy_map_snapshot *snapshot)
{
	struct mcp_resource_policy_key key = {};
	struct mcp_resource_policy_key next_key = {};
	int have_key = 0;

	if (fd < 0 || !snapshot)
		return 0;

	snapshot->resource_entry_count = 0;
	while (bpf_map_get_next_key(fd, have_key ? &key : NULL, &next_key) == 0) {
		struct resource_policy_entry *entry;

		if (snapshot->resource_entry_count >= MCP_GUARD_MAX_RULES)
			return -ENOSPC;

		entry = &snapshot->resource_entries[snapshot->resource_entry_count];
		entry->key = next_key;
		if (bpf_map_lookup_elem(fd, &entry->key, &entry->value) != 0)
			return -errno;

		snapshot->resource_entry_count++;
		key = next_key;
		have_key = 1;
	}

	return 0;
}

static int snapshot_comm_scopes(int fd, struct policy_map_snapshot *snapshot)
{
	struct mcp_comm_scope_key key = {};
	struct mcp_comm_scope_key next_key = {};
	int have_key = 0;

	if (fd < 0 || !snapshot)
		return 0;

	snapshot->comm_entry_count = 0;
	while (bpf_map_get_next_key(fd, have_key ? &key : NULL, &next_key) == 0) {
		struct comm_scope_entry *entry;

		if (snapshot->comm_entry_count >= MCP_GUARD_MAX_SCOPES)
			return -ENOSPC;
		entry = &snapshot->comm_entries[snapshot->comm_entry_count];
		entry->key = next_key;
		if (bpf_map_lookup_elem(fd, &entry->key, &entry->value) != 0)
			return -errno;
		snapshot->comm_entry_count++;
		key = next_key;
		have_key = 1;
	}
	return 0;
}

static int snapshot_id_scopes(int fd, struct id_scope_entry *entries,
			      __u32 *entry_count)
{
	__u32 key = 0;
	__u32 next_key = 0;
	int have_key = 0;

	if (entry_count)
		*entry_count = 0;
	if (fd < 0 || !entries || !entry_count)
		return 0;

	while (bpf_map_get_next_key(fd, have_key ? &key : NULL, &next_key) == 0) {
		struct id_scope_entry *entry;

		if (*entry_count >= MCP_GUARD_MAX_SCOPES)
			return -ENOSPC;
		entry = &entries[*entry_count];
		entry->key = next_key;
		if (bpf_map_lookup_elem(fd, &entry->key, &entry->value) != 0)
			return -errno;
		(*entry_count)++;
		key = next_key;
		have_key = 1;
	}
	return 0;
}

static int snapshot_policy_maps(int rules_fd, int path_trie_fd,
				int command_trie_fd, int network_trie_fd,
				int resource_hash_fd,
				int scope_comm_fd, int scope_pid_fd,
				int scope_tgid_fd, int config_fd,
				struct policy_map_snapshot *snapshot)
{
	int err;

	if (!snapshot)
		return -EINVAL;
	memset(snapshot, 0, sizeof(*snapshot));

	err = snapshot_rules(rules_fd, snapshot);
	if (err)
		return err;
	err = snapshot_config(config_fd, snapshot);
	if (err)
		return err;
	err = snapshot_path_trie(path_trie_fd, snapshot);
	if (err)
		return err;
	err = snapshot_command_trie(command_trie_fd, snapshot);
	if (err)
		return err;
	err = snapshot_network_trie(network_trie_fd, snapshot);
	if (err)
		return err;
	err = snapshot_resource_hash(resource_hash_fd, snapshot);
	if (err)
		return err;
	err = snapshot_comm_scopes(scope_comm_fd, snapshot);
	if (err)
		return err;
	err = snapshot_id_scopes(scope_pid_fd, snapshot->pid_entries,
				 &snapshot->pid_entry_count);
	if (err)
		return err;
	return snapshot_id_scopes(scope_tgid_fd, snapshot->tgid_entries,
				  &snapshot->tgid_entry_count);
}

static int clear_path_trie(int path_trie_fd)
{
	struct mcp_path_lpm_key key = {};

	if (path_trie_fd < 0)
		return 0;

	while (bpf_map_get_next_key(path_trie_fd, NULL, &key) == 0)
		bpf_map_delete_elem(path_trie_fd, &key);
	return 0;
}

static int clear_path_generation(int fd, __u32 generation)
{
	struct mcp_path_lpm_key key = {};
	struct mcp_path_lpm_key next_key = {};
	int have_key = 0;

	if (fd < 0)
		return 0;

	while (bpf_map_get_next_key(fd, have_key ? &key : NULL, &next_key) == 0) {
		key = next_key;
		have_key = 1;
		if (next_key.generation == generation) {
			bpf_map_delete_elem(fd, &next_key);
			have_key = 0;
		}
	}
	return 0;
}

static int clear_command_generation(int fd, __u32 generation)
{
	struct mcp_command_lpm_key key = {};
	struct mcp_command_lpm_key next_key = {};
	int have_key = 0;

	if (fd < 0)
		return 0;

	while (bpf_map_get_next_key(fd, have_key ? &key : NULL, &next_key) == 0) {
		key = next_key;
		have_key = 1;
		if (next_key.generation == generation) {
			bpf_map_delete_elem(fd, &next_key);
			have_key = 0;
		}
	}
	return 0;
}

static int clear_network_generation(int fd, __u32 generation)
{
	struct mcp_network_lpm_key key = {};
	struct mcp_network_lpm_key next_key = {};
	int have_key = 0;

	if (fd < 0)
		return 0;

	while (bpf_map_get_next_key(fd, have_key ? &key : NULL, &next_key) == 0) {
		key = next_key;
		have_key = 1;
		if (next_key.generation == generation) {
			bpf_map_delete_elem(fd, &next_key);
			have_key = 0;
		}
	}
	return 0;
}

static int clear_resource_generation(int fd, __u32 generation)
{
	struct mcp_resource_policy_key key = {};
	struct mcp_resource_policy_key next_key = {};
	int have_key = 0;

	if (fd < 0)
		return 0;

	while (bpf_map_get_next_key(fd, have_key ? &key : NULL, &next_key) == 0) {
		key = next_key;
		have_key = 1;
		if (next_key.generation == generation) {
			bpf_map_delete_elem(fd, &next_key);
			have_key = 0;
		}
	}
	return 0;
}

static __u32 path_prefix_bits(const char *path)
{
	return 32 + (__u32)strnlen(path, MCP_GUARD_PATH_LPM_LEN) * 8;
}

static __u32 command_prefix_bits(const char *command)
{
	return 32 + (__u32)strnlen(command, MCP_GUARD_RULE_VALUE_LEN) * 8;
}

static __u32 ipv4_prefix_bits(__u32 mask)
{
	__u32 host_mask = ntohl(mask);
	__u32 bits = 0;

	for (__u32 i = 0; i < 32; i++) {
		if (!(host_mask & (1U << (31 - i))))
			break;
		bits++;
	}
	return 32 + 32 + bits;
}

static void indexed_value_from_rule(struct mcp_indexed_policy_value *value,
				    const struct mcp_policy_rule *rule)
{
	memset(value, 0, sizeof(*value));
	value->enabled = rule->enabled;
	value->rule_id = rule->rule_id;
	value->action = rule->action;
	value->hook_mask = rule->hook_mask;
	value->flags = rule->flags;
	value->value_len = rule->value_len;
	value->port = rule->port;
	value->ipv4_addr = rule->ipv4_addr;
	value->ipv4_mask = rule->ipv4_mask;
	value->resource_id = rule->resource_id;
	snprintf(value->name, sizeof(value->name), "%s", rule->name);
}

static int write_path_trie(int path_trie_fd, const struct policy_load_state *state,
			   __u32 generation)
{
	if (path_trie_fd < 0)
		return 0;

	for (__u32 i = 0; i < state->next_index; i++) {
		const struct mcp_policy_rule *rule = &state->rules[i];
		struct mcp_path_lpm_key key = {};
		struct mcp_path_policy_value value = {};

		if (rule->rule_type != MCP_GUARD_RULE_PATH_PREFIX)
			continue;
		if (!rule->value[0] || rule->value[0] != '/')
			return -EINVAL;

		key.prefixlen = path_prefix_bits(rule->value);
		key.generation = generation;
		memcpy(key.path, rule->value, strnlen(rule->value, sizeof(key.path)));

		value.enabled = rule->enabled;
		value.rule_id = rule->rule_id;
		value.action = rule->action;
		value.hook_mask = rule->hook_mask;
		value.flags = rule->flags;
		value.value_len = rule->value_len;
		value.resource_id = rule->resource_id;
		snprintf(value.name, sizeof(value.name), "%s", rule->name);

		if (bpf_map_update_elem(path_trie_fd, &key, &value, BPF_ANY) != 0)
			return -errno;
	}

	return 0;
}

static int write_command_trie(int fd, const struct policy_load_state *state,
			      __u32 generation)
{
	if (fd < 0)
		return 0;

	for (__u32 i = 0; i < state->next_index; i++) {
		const struct mcp_policy_rule *rule = &state->rules[i];
		struct mcp_command_lpm_key key = {};
		struct mcp_indexed_policy_value value = {};

		if (rule->rule_type != MCP_GUARD_RULE_COMMAND_PREFIX)
			continue;
		if (!rule->value[0])
			return -EINVAL;

		key.prefixlen = command_prefix_bits(rule->value);
		key.generation = generation;
		snprintf(key.command, sizeof(key.command), "%s", rule->value);
		indexed_value_from_rule(&value, rule);

		if (bpf_map_update_elem(fd, &key, &value, BPF_ANY) != 0)
			return -errno;
	}

	return 0;
}

static int write_network_trie(int fd, const struct policy_load_state *state,
			      __u32 generation)
{
	if (fd < 0)
		return 0;

	for (__u32 i = 0; i < state->next_index; i++) {
		const struct mcp_policy_rule *rule = &state->rules[i];
		struct mcp_network_lpm_key key = {};
		struct mcp_indexed_policy_value value = {};

		if (rule->rule_type != MCP_GUARD_RULE_IPV4_CONNECT)
			continue;

		key.prefixlen = ipv4_prefix_bits(rule->ipv4_mask);
		key.generation = generation;
		key.port = rule->port;
		key.ipv4_addr = rule->ipv4_addr;
		indexed_value_from_rule(&value, rule);

		if (bpf_map_update_elem(fd, &key, &value, BPF_ANY) != 0)
			return -errno;
	}

	return 0;
}

static int write_resource_hash(int fd, const struct policy_load_state *state,
			       __u32 generation)
{
	if (fd < 0)
		return 0;

	for (__u32 i = 0; i < state->next_index; i++) {
		const struct mcp_policy_rule *rule = &state->rules[i];
		struct mcp_resource_policy_key key = {};
		struct mcp_indexed_policy_value value = {};

		if (!rule->resource_id)
			continue;
		key.generation = generation;
		key.rule_type = rule->rule_type;
		key.resource_id = rule->resource_id;
		indexed_value_from_rule(&value, rule);

		if (bpf_map_update_elem(fd, &key, &value, BPF_ANY) != 0)
			return -errno;
	}

	return 0;
}

static int clear_comm_scopes(int fd)
{
	struct mcp_comm_scope_key key = {};

	if (fd < 0)
		return 0;

	while (bpf_map_get_next_key(fd, NULL, &key) == 0)
		bpf_map_delete_elem(fd, &key);
	return 0;
}

static int clear_id_scopes(int fd)
{
	__u32 key = 0;

	if (fd < 0)
		return 0;

	while (bpf_map_get_next_key(fd, NULL, &key) == 0)
		bpf_map_delete_elem(fd, &key);
	return 0;
}

static int write_scope_maps(int scope_comm_fd, int scope_pid_fd,
			    int scope_tgid_fd,
			    const struct scope_load_state *scope,
			    const struct mcp_policy_config *config)
{
	struct mcp_scope_value value = {};
	int err;

	if (!scope || !config)
		return -EINVAL;

	value.profile_id = config->profile_id;
	value.agent_id = config->agent_id;

	err = clear_comm_scopes(scope_comm_fd);
	if (err)
		return err;
	err = clear_id_scopes(scope_pid_fd);
	if (err)
		return err;
	err = clear_id_scopes(scope_tgid_fd);
	if (err)
		return err;

	value.selector_type = MCP_GUARD_SCOPE_SELECTOR_COMM;
	for (__u32 i = 0; i < scope->comm_count; i++) {
		if (bpf_map_update_elem(scope_comm_fd, &scope->comm_keys[i],
					&value, BPF_ANY) != 0)
			return -errno;
	}

	value.selector_type = MCP_GUARD_SCOPE_SELECTOR_PID;
	for (__u32 i = 0; i < scope->pid_count; i++) {
		if (bpf_map_update_elem(scope_pid_fd, &scope->pid_keys[i],
					&value, BPF_ANY) != 0)
			return -errno;
	}

	value.selector_type = MCP_GUARD_SCOPE_SELECTOR_TGID;
	for (__u32 i = 0; i < scope->tgid_count; i++) {
		if (bpf_map_update_elem(scope_tgid_fd, &scope->tgid_keys[i],
					&value, BPF_ANY) != 0)
			return -errno;
	}

	return 0;
}

static int restore_path_trie(int path_trie_fd,
			     const struct policy_map_snapshot *snapshot)
{
	int err;

	if (path_trie_fd < 0 || !snapshot)
		return 0;

	err = clear_path_trie(path_trie_fd);
	if (err)
		return err;

	for (__u32 i = 0; i < snapshot->path_entry_count; i++) {
		const struct path_policy_entry *entry = &snapshot->path_entries[i];

		if (bpf_map_update_elem(path_trie_fd, &entry->key,
					&entry->value, BPF_ANY) != 0)
			return -errno;
	}

	return 0;
}

static int restore_command_trie(int fd, const struct policy_map_snapshot *snapshot)
{
	int err;

	if (fd < 0 || !snapshot)
		return 0;

	err = clear_command_generation(fd, snapshot->config.active_generation);
	if (err)
		return err;

	for (__u32 i = 0; i < snapshot->command_entry_count; i++) {
		const struct command_policy_entry *entry =
			&snapshot->command_entries[i];

		if (bpf_map_update_elem(fd, &entry->key, &entry->value,
					BPF_ANY) != 0)
			return -errno;
	}

	return 0;
}

static int restore_network_trie(int fd, const struct policy_map_snapshot *snapshot)
{
	int err;

	if (fd < 0 || !snapshot)
		return 0;

	err = clear_network_generation(fd, snapshot->config.active_generation);
	if (err)
		return err;

	for (__u32 i = 0; i < snapshot->network_entry_count; i++) {
		const struct network_policy_entry *entry =
			&snapshot->network_entries[i];

		if (bpf_map_update_elem(fd, &entry->key, &entry->value,
					BPF_ANY) != 0)
			return -errno;
	}

	return 0;
}

static int restore_resource_hash(int fd, const struct policy_map_snapshot *snapshot)
{
	int err;

	if (fd < 0 || !snapshot)
		return 0;

	err = clear_resource_generation(fd, snapshot->config.active_generation);
	if (err)
		return err;

	for (__u32 i = 0; i < snapshot->resource_entry_count; i++) {
		const struct resource_policy_entry *entry =
			&snapshot->resource_entries[i];

		if (bpf_map_update_elem(fd, &entry->key, &entry->value,
					BPF_ANY) != 0)
			return -errno;
	}

	return 0;
}

static int restore_policy_maps(int rules_fd, int path_trie_fd,
			       int command_trie_fd, int network_trie_fd,
			       int resource_hash_fd,
			       int config_fd,
			       int scope_comm_fd, int scope_pid_fd,
			       int scope_tgid_fd,
			       const struct policy_map_snapshot *snapshot)
{
	__u32 key = MCP_GUARD_CONFIG_KEY;
	int first_err = 0;
	int err;

	if (!snapshot)
		return -EINVAL;

	for (__u32 i = 0; i < MCP_GUARD_MAX_RULES; i++) {
		if (bpf_map_update_elem(rules_fd, &i, &snapshot->rules[i],
					BPF_ANY) != 0 && !first_err)
			first_err = -errno;
	}

	err = restore_path_trie(path_trie_fd, snapshot);
	if (err && !first_err)
		first_err = err;

	err = restore_command_trie(command_trie_fd, snapshot);
	if (err && !first_err)
		first_err = err;

	err = restore_network_trie(network_trie_fd, snapshot);
	if (err && !first_err)
		first_err = err;

	err = restore_resource_hash(resource_hash_fd, snapshot);
	if (err && !first_err)
		first_err = err;

	err = clear_comm_scopes(scope_comm_fd);
	if (err && !first_err)
		first_err = err;
	for (__u32 i = 0; i < snapshot->comm_entry_count; i++) {
		if (bpf_map_update_elem(scope_comm_fd,
					&snapshot->comm_entries[i].key,
					&snapshot->comm_entries[i].value,
					BPF_ANY) != 0 && !first_err)
			first_err = -errno;
	}

	err = clear_id_scopes(scope_pid_fd);
	if (err && !first_err)
		first_err = err;
	for (__u32 i = 0; i < snapshot->pid_entry_count; i++) {
		if (bpf_map_update_elem(scope_pid_fd,
					&snapshot->pid_entries[i].key,
					&snapshot->pid_entries[i].value,
					BPF_ANY) != 0 && !first_err)
			first_err = -errno;
	}

	err = clear_id_scopes(scope_tgid_fd);
	if (err && !first_err)
		first_err = err;
	for (__u32 i = 0; i < snapshot->tgid_entry_count; i++) {
		if (bpf_map_update_elem(scope_tgid_fd,
					&snapshot->tgid_entries[i].key,
					&snapshot->tgid_entries[i].value,
					BPF_ANY) != 0 && !first_err)
			first_err = -errno;
	}

	if (snapshot->have_config &&
	    bpf_map_update_elem(config_fd, &key, &snapshot->config, BPF_ANY) != 0 &&
	    !first_err)
		first_err = -errno;

	return first_err;
}

static int bump_epoch(int epoch_fd, __u64 *new_epoch)
{
	__u32 key = MCP_GUARD_EPOCH_KEY;
	__u64 epoch = 0;

	bpf_map_lookup_elem(epoch_fd, &key, &epoch);
	epoch++;
	if (!epoch)
		epoch = 1;

	if (bpf_map_update_elem(epoch_fd, &key, &epoch, BPF_ANY) != 0)
		return -errno;

	if (new_epoch)
		*new_epoch = epoch;
	return 0;
}

static int validate_policy_state(const struct policy_load_state *state,
				 const struct mcp_policy_config *config)
{
	if (!state || !config)
		return -EINVAL;
	if (state->next_index > MCP_GUARD_MAX_RULES)
		return -EINVAL;
	if (config->rule_count != state->next_index)
		return -EINVAL;
	if (!config->profile_id || !config->agent_id)
		return -EINVAL;
	if (config->scope_mode == MCP_GUARD_SCOPE_SCOPED &&
	    !config->scope_count)
		return -EINVAL;
	if (config->scope_mode != MCP_GUARD_SCOPE_SYSTEM_WIDE &&
	    config->scope_mode != MCP_GUARD_SCOPE_SCOPED)
		return -EINVAL;

	for (__u32 i = 0; i < state->next_index; i++) {
		const struct mcp_policy_rule *rule = &state->rules[i];

		if (!rule->enabled)
			return -EINVAL;
		if (!rule->rule_id || rule->rule_id > MCP_GUARD_MAX_RULES)
			return -EINVAL;
		if (rule->action != MCP_GUARD_ACTION_ALLOW &&
		    rule->action != MCP_GUARD_ACTION_DENY &&
		    rule->action != MCP_GUARD_ACTION_AUDIT)
			return -EINVAL;
		if (!rule->hook_mask)
			return -EINVAL;
		if (!rule->value_len || rule->value_len >= MCP_GUARD_RULE_VALUE_LEN)
			return -EINVAL;
		if (rule->rule_type == MCP_GUARD_RULE_PATH_PREFIX &&
		    rule->value[0] != '/')
			return -EINVAL;
	}

	return 0;
}

static int join_policy_path(char *out, size_t out_len,
			    const char *dir, const char *file)
{
	int written = snprintf(out, out_len, "%s/%s", dir, file);

	if (written < 0 || (size_t)written >= out_len)
		return -ENAMETOOLONG;
	return 0;
}

int mcp_policy_load_dir(const char *policy_dir,
			int rules_fd,
			int path_trie_fd,
			int command_trie_fd,
			int network_trie_fd,
			int resource_hash_fd,
			int scope_comm_fd,
			int scope_pid_fd,
			int scope_tgid_fd,
			int config_fd,
			int epoch_fd,
			struct mcp_policy_load_result *result)
{
	struct policy_load_state state = {};
	struct scope_load_state scope = {};
	struct mcp_policy_config config = {
		.default_action = MCP_GUARD_ACTION_ALLOW,
		.enforce = 1,
		.audit_allowed = 0,
		.flags = MCP_GUARD_POLICY_F_SKIP_DIR_READ |
			 MCP_GUARD_POLICY_F_CACHE_FILE_FOLLOWUPS |
			 MCP_GUARD_POLICY_F_DENY_TAILCALL_FAIL,
		.profile_id = 1,
		.agent_id = 1,
		.scope_mode = MCP_GUARD_SCOPE_SYSTEM_WIDE,
		.scope_count = 0,
		.profile_name = "default-mcp-agent",
	};
	char path[PATH_MAX];
	__u32 key = MCP_GUARD_CONFIG_KEY;
	__u64 epoch = 0;
	struct policy_map_snapshot snapshot = {};
	int err;

	if (!policy_dir || rules_fd < 0 || config_fd < 0 || epoch_fd < 0)
		return -EINVAL;

	err = join_policy_path(path, sizeof(path), policy_dir, "default_policy.json");
	if (err)
		return err;
	err = load_config_file(path, &config);
	if (err)
		return err;

	err = join_policy_path(path, sizeof(path), policy_dir,
			       "mcp_agent_profile.json");
	if (err)
		return err;
	err = load_profile_file(path, &config, &scope);
	if (err)
		return err;

	err = join_policy_path(path, sizeof(path), policy_dir, "dangerous_paths.json");
	if (err)
		return err;
	err = load_rule_file(path, MCP_GUARD_RULE_PATH_PREFIX, &state);
	if (err)
		return err;

	err = join_policy_path(path, sizeof(path), policy_dir, "dangerous_commands.json");
	if (err)
		return err;
	err = load_rule_file(path, MCP_GUARD_RULE_COMMAND_PREFIX, &state);
	if (err)
		return err;

	err = join_policy_path(path, sizeof(path), policy_dir, "dangerous_network.json");
	if (err)
		return err;
	err = load_rule_file(path, MCP_GUARD_RULE_IPV4_CONNECT, &state);
	if (err)
		return err;

	config.rule_count = state.next_index;
	config.active_generation = 1;

	err = snapshot_policy_maps(rules_fd, path_trie_fd, command_trie_fd,
				   network_trie_fd, resource_hash_fd,
				   scope_comm_fd,
				   scope_pid_fd, scope_tgid_fd, config_fd,
				   &snapshot);
	if (err)
		return err;
	if (snapshot.have_config)
		config.active_generation = snapshot.config.active_generation + 1;
	if (!config.active_generation)
		config.active_generation = 1;

	err = validate_policy_state(&state, &config);
	if (err)
		return err;

	err = clear_path_generation(path_trie_fd, config.active_generation);
	if (err) {
		restore_policy_maps(rules_fd, path_trie_fd, command_trie_fd,
				    network_trie_fd, resource_hash_fd, config_fd,
				    scope_comm_fd, scope_pid_fd, scope_tgid_fd,
				    &snapshot);
		return err;
	}
	err = clear_command_generation(command_trie_fd, config.active_generation);
	if (err) {
		restore_policy_maps(rules_fd, path_trie_fd, command_trie_fd,
				    network_trie_fd, resource_hash_fd, config_fd,
				    scope_comm_fd, scope_pid_fd, scope_tgid_fd,
				    &snapshot);
		return err;
	}
	err = clear_network_generation(network_trie_fd, config.active_generation);
	if (err) {
		restore_policy_maps(rules_fd, path_trie_fd, command_trie_fd,
				    network_trie_fd, resource_hash_fd, config_fd,
				    scope_comm_fd, scope_pid_fd, scope_tgid_fd,
				    &snapshot);
		return err;
	}
	err = clear_resource_generation(resource_hash_fd, config.active_generation);
	if (err) {
		restore_policy_maps(rules_fd, path_trie_fd, command_trie_fd,
				    network_trie_fd, resource_hash_fd, config_fd,
				    scope_comm_fd, scope_pid_fd, scope_tgid_fd,
				    &snapshot);
		return err;
	}
	err = write_path_trie(path_trie_fd, &state, config.active_generation);
	if (err) {
		clear_path_generation(path_trie_fd, config.active_generation);
		restore_policy_maps(rules_fd, path_trie_fd, command_trie_fd,
				    network_trie_fd, resource_hash_fd, config_fd,
				    scope_comm_fd, scope_pid_fd, scope_tgid_fd,
				    &snapshot);
		return err;
	}
	err = write_command_trie(command_trie_fd, &state, config.active_generation);
	if (err) {
		clear_path_generation(path_trie_fd, config.active_generation);
		clear_command_generation(command_trie_fd, config.active_generation);
		restore_policy_maps(rules_fd, path_trie_fd, command_trie_fd,
				    network_trie_fd, resource_hash_fd, config_fd,
				    scope_comm_fd, scope_pid_fd, scope_tgid_fd,
				    &snapshot);
		return err;
	}
	err = write_network_trie(network_trie_fd, &state, config.active_generation);
	if (err) {
		clear_path_generation(path_trie_fd, config.active_generation);
		clear_command_generation(command_trie_fd, config.active_generation);
		clear_network_generation(network_trie_fd, config.active_generation);
		restore_policy_maps(rules_fd, path_trie_fd, command_trie_fd,
				    network_trie_fd, resource_hash_fd, config_fd,
				    scope_comm_fd, scope_pid_fd, scope_tgid_fd,
				    &snapshot);
		return err;
	}
	err = write_resource_hash(resource_hash_fd, &state, config.active_generation);
	if (err) {
		clear_path_generation(path_trie_fd, config.active_generation);
		clear_command_generation(command_trie_fd, config.active_generation);
		clear_network_generation(network_trie_fd, config.active_generation);
		clear_resource_generation(resource_hash_fd, config.active_generation);
		restore_policy_maps(rules_fd, path_trie_fd, command_trie_fd,
				    network_trie_fd, resource_hash_fd, config_fd,
				    scope_comm_fd, scope_pid_fd, scope_tgid_fd,
				    &snapshot);
		return err;
	}
	err = write_rules(rules_fd, &state);
	if (err) {
		clear_path_generation(path_trie_fd, config.active_generation);
		clear_command_generation(command_trie_fd, config.active_generation);
		clear_network_generation(network_trie_fd, config.active_generation);
		clear_resource_generation(resource_hash_fd, config.active_generation);
		restore_policy_maps(rules_fd, path_trie_fd, command_trie_fd,
				    network_trie_fd, resource_hash_fd, config_fd,
				    scope_comm_fd, scope_pid_fd, scope_tgid_fd,
				    &snapshot);
		return err;
	}
	err = write_scope_maps(scope_comm_fd, scope_pid_fd, scope_tgid_fd,
			       &scope, &config);
	if (err) {
		clear_path_generation(path_trie_fd, config.active_generation);
		clear_command_generation(command_trie_fd, config.active_generation);
		clear_network_generation(network_trie_fd, config.active_generation);
		clear_resource_generation(resource_hash_fd, config.active_generation);
		restore_policy_maps(rules_fd, path_trie_fd, command_trie_fd,
				    network_trie_fd, resource_hash_fd, config_fd,
				    scope_comm_fd, scope_pid_fd, scope_tgid_fd,
				    &snapshot);
		return err;
	}
	if (bpf_map_update_elem(config_fd, &key, &config, BPF_ANY) != 0) {
		err = -errno;
		clear_path_generation(path_trie_fd, config.active_generation);
		clear_command_generation(command_trie_fd, config.active_generation);
		clear_network_generation(network_trie_fd, config.active_generation);
		clear_resource_generation(resource_hash_fd, config.active_generation);
		restore_policy_maps(rules_fd, path_trie_fd, command_trie_fd,
				    network_trie_fd, resource_hash_fd, config_fd,
				    scope_comm_fd, scope_pid_fd, scope_tgid_fd,
				    &snapshot);
		return err;
	}

	err = bump_epoch(epoch_fd, &epoch);
	if (err) {
		restore_policy_maps(rules_fd, path_trie_fd, command_trie_fd,
				    network_trie_fd, resource_hash_fd, config_fd,
				    scope_comm_fd, scope_pid_fd, scope_tgid_fd,
				    &snapshot);
		return err;
	}

	if (snapshot.have_config &&
	    snapshot.config.active_generation != config.active_generation) {
		clear_path_generation(path_trie_fd, snapshot.config.active_generation);
		clear_command_generation(command_trie_fd, snapshot.config.active_generation);
		clear_network_generation(network_trie_fd, snapshot.config.active_generation);
		clear_resource_generation(resource_hash_fd, snapshot.config.active_generation);
	}

	if (result) {
		result->rule_count = state.next_index;
		result->flags = config.flags;
		result->active_generation = config.active_generation;
		result->profile_id = config.profile_id;
		result->agent_id = config.agent_id;
		result->scope_mode = config.scope_mode;
		result->scope_count = config.scope_count;
		snprintf(result->profile_name, sizeof(result->profile_name), "%s",
			 config.profile_name);
		result->epoch = epoch;
	}

	return 0;
}
