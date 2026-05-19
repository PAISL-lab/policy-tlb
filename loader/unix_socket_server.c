// SPDX-License-Identifier: Apache-2.0
#include "unix_socket_server.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "../include/common.h"

struct mcp_unix_socket_server {
	int fd;
	int clients[MCP_GUARD_MAX_CLIENTS];
	char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
};

static int set_nonblock(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);

	if (flags < 0)
		return -errno;
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
		return -errno;
	return 0;
}

static const char *hook_name(__u32 hook_id)
{
	switch (hook_id) {
	case MCP_GUARD_HOOK_EXEC:
		return "exec";
	case MCP_GUARD_HOOK_FILE_OPEN:
		return "file_open";
	case MCP_GUARD_HOOK_FILE_READ:
		return "file_read";
	case MCP_GUARD_HOOK_FILE_WRITE:
		return "file_write";
	case MCP_GUARD_HOOK_SOCKET_CONNECT:
		return "socket_connect";
	default:
		return "unknown";
	}
}

static const char *action_name(__u32 action)
{
	switch (action) {
	case MCP_GUARD_ACTION_DENY:
		return "deny";
	case MCP_GUARD_ACTION_AUDIT:
		return "audit";
	case MCP_GUARD_ACTION_ALLOW:
		return "allow";
	default:
		return "unknown";
	}
}

static const char *layer_name(__u32 layer)
{
	switch (layer) {
	case MCP_GUARD_LAYER_L1:
		return "L1";
	case MCP_GUARD_LAYER_L2:
		return "L2";
	case MCP_GUARD_LAYER_L3:
		return "L3";
	default:
		return "unknown";
	}
}

static void close_client(struct mcp_unix_socket_server *server, int index)
{
	close(server->clients[index]);
	server->clients[index] = -1;
}

static void publish_line(struct mcp_unix_socket_server *server,
			 const char *line, size_t len)
{
	if (!server || !line || !len)
		return;

	mcp_unix_socket_server_accept(server);
	for (int i = 0; i < MCP_GUARD_MAX_CLIENTS; i++) {
		if (server->clients[i] < 0)
			continue;
		if (write(server->clients[i], line, len) < 0)
			close_client(server, i);
	}
}

int mcp_unix_socket_server_start(const char *path,
				 struct mcp_unix_socket_server **out)
{
	struct mcp_unix_socket_server *server;
	struct sockaddr_un addr = {};
	int err;

	if (!path || !out)
		return -EINVAL;

	server = calloc(1, sizeof(*server));
	if (!server)
		return -ENOMEM;

	for (int i = 0; i < MCP_GUARD_MAX_CLIENTS; i++)
		server->clients[i] = -1;

	server->fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (server->fd < 0) {
		err = -errno;
		free(server);
		return err;
	}

	snprintf(server->path, sizeof(server->path), "%s", path);
	unlink(server->path);

	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", server->path);

	if (bind(server->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		err = -errno;
		mcp_unix_socket_server_stop(server);
		return err;
	}

	if (listen(server->fd, MCP_GUARD_MAX_CLIENTS) < 0) {
		err = -errno;
		mcp_unix_socket_server_stop(server);
		return err;
	}

	err = set_nonblock(server->fd);
	if (err) {
		mcp_unix_socket_server_stop(server);
		return err;
	}

	*out = server;
	return 0;
}

void mcp_unix_socket_server_accept(struct mcp_unix_socket_server *server)
{
	if (!server)
		return;

	for (;;) {
		int client = accept(server->fd, NULL, NULL);
		int slot = -1;

		if (client < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return;
			return;
		}

		set_nonblock(client);
		for (int i = 0; i < MCP_GUARD_MAX_CLIENTS; i++) {
			if (server->clients[i] < 0) {
				slot = i;
				break;
			}
		}

		if (slot < 0) {
			close(client);
			continue;
		}
		server->clients[slot] = client;
	}
}

void mcp_unix_socket_server_publish(struct mcp_unix_socket_server *server,
				    const struct mcp_event *event)
{
	char line[768];
	int len;

	if (!server || !event)
		return;

	len = snprintf(line, sizeof(line),
	       "{\"type\":\"event\",\"ts_ns\":%llu,\"pid\":%u,\"uid\":%u,\"hook\":\"%s\","
		       "\"profile_id\":%u,\"agent_id\":%u,"
		       "\"action\":\"%s\",\"layer\":\"%s\",\"duration_ns\":%llu,"
		       "\"rule_id\":%u,\"error\":%u,"
		       "\"path\":\"%s\",\"rule\":\"%s\",\"port\":%u}\n",
		       (unsigned long long)event->ts_ns, event->pid, event->uid,
		       hook_name(event->hook_id), event->profile_id,
		       event->agent_id, action_name(event->action),
		       layer_name(event->layer),
		       (unsigned long long)event->duration_ns,
		       event->rule_id, event->error, event->path,
		       event->rule_name, event->port);
	if (len <= 0)
		return;

	publish_line(server, line, (size_t)len);
}

void mcp_unix_socket_server_publish_metrics(struct mcp_unix_socket_server *server,
					    __u64 total_count,
					    __u64 l1_count,
					    __u64 l2_count,
					    __u64 l3_count)
{
	char line[512];
	int len;

	if (!server)
		return;

	len = snprintf(line, sizeof(line),
		       "{\"type\":\"metrics_snapshot\",\"total_count\":%llu,"
		       "\"layers\":{\"L1\":%llu,\"L2\":%llu,\"L3\":%llu},"
		       "\"ratios\":{\"L1\":%.6f,\"L2\":%.6f,\"L3\":%.6f}}\n",
		       (unsigned long long)total_count,
		       (unsigned long long)l1_count,
		       (unsigned long long)l2_count,
		       (unsigned long long)l3_count,
		       total_count ? (double)l1_count / (double)total_count : 0.0,
		       total_count ? (double)l2_count / (double)total_count : 0.0,
		       total_count ? (double)l3_count / (double)total_count : 0.0);
	if (len <= 0)
		return;

	publish_line(server, line, (size_t)len);
}

void mcp_unix_socket_server_publish_reload(struct mcp_unix_socket_server *server,
					   int success,
					   __u32 rule_count,
					   __u32 active_generation,
					   __u64 epoch,
					   const char *error)
{
	char line[512];
	int len;

	if (!server)
		return;

	len = snprintf(line, sizeof(line),
		       "{\"type\":\"reload_result\",\"success\":%s,"
		       "\"rule_count\":%u,\"active_generation\":%u,"
		       "\"epoch\":%llu,\"error\":\"%s\"}\n",
		       success ? "true" : "false", rule_count,
		       active_generation, (unsigned long long)epoch,
		       error ? error : "");
	if (len <= 0)
		return;

	publish_line(server, line, (size_t)len);
}

void mcp_unix_socket_server_stop(struct mcp_unix_socket_server *server)
{
	if (!server)
		return;

	for (int i = 0; i < MCP_GUARD_MAX_CLIENTS; i++) {
		if (server->clients[i] >= 0)
			close_client(server, i);
	}

	if (server->fd >= 0)
		close(server->fd);
	if (server->path[0])
		unlink(server->path);
	free(server);
}
