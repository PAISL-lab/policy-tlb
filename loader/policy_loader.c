#include "policy_loader.h"

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/common.h"

struct policy_load_state {
	int rules_fd;
	__u32 next_index;
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

static int add_rule(struct policy_load_state *state, struct mcp_policy_rule *rule)
{
	__u32 index;
	int err;

	if (state->next_index >= MCP_GUARD_MAX_RULES)
		return -ENOSPC;

	index = state->next_index;
	rule->enabled = 1;
	rule->rule_id = index + 1;
	err = bpf_map_update_elem(state->rules_fd, &index, rule, BPF_ANY);
	if (err)
		return -errno;

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

		rule.rule_type = forced_type;
		rule.action = parse_action(action);
		rule.hook_mask = default_hook_mask(rule.rule_type);
		rule.value_len = strnlen(value, sizeof(rule.value));
		snprintf(rule.value, sizeof(rule.value), "%s", value);
		snprintf(rule.name, sizeof(rule.name), "%s", name[0] ? name : value);

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

	free(buf);
	return 0;
}

static int clear_rules(int rules_fd)
{
	struct mcp_policy_rule empty = {};

	for (__u32 i = 0; i < MCP_GUARD_MAX_RULES; i++) {
		if (bpf_map_update_elem(rules_fd, &i, &empty, BPF_ANY) != 0)
			return -errno;
	}
	return 0;
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
			int config_fd,
			int epoch_fd,
			struct mcp_policy_load_result *result)
{
	struct policy_load_state state = {
		.rules_fd = rules_fd,
	};
	struct mcp_policy_config config = {
		.default_action = MCP_GUARD_ACTION_ALLOW,
		.enforce = 1,
		.audit_allowed = 0,
	};
	char path[PATH_MAX];
	__u32 key = MCP_GUARD_CONFIG_KEY;
	__u64 epoch = 0;
	int err;

	if (!policy_dir || rules_fd < 0 || config_fd < 0 || epoch_fd < 0)
		return -EINVAL;

	err = clear_rules(rules_fd);
	if (err)
		return err;

	err = join_policy_path(path, sizeof(path), policy_dir, "default_policy.json");
	if (err)
		return err;
	err = load_config_file(path, &config);
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
	if (bpf_map_update_elem(config_fd, &key, &config, BPF_ANY) != 0)
		return -errno;

	err = bump_epoch(epoch_fd, &epoch);
	if (err)
		return err;

	if (result) {
		result->rule_count = state.next_index;
		result->epoch = epoch;
	}

	return 0;
}
