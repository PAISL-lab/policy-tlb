// SPDX-License-Identifier: Apache-2.0
#ifndef MCP_GUARD_UNIX_SOCKET_SERVER_H
#define MCP_GUARD_UNIX_SOCKET_SERVER_H

#include <stddef.h>

#include "../include/event.h"

struct mcp_unix_socket_server;

int mcp_unix_socket_server_start(const char *path,
				 struct mcp_unix_socket_server **out);
void mcp_unix_socket_server_accept(struct mcp_unix_socket_server *server);
void mcp_unix_socket_server_publish(struct mcp_unix_socket_server *server,
				    const struct mcp_event *event);
void mcp_unix_socket_server_publish_metrics(struct mcp_unix_socket_server *server,
					    __u64 total_count,
					    __u64 l1_count,
					    __u64 l2_count,
					    __u64 l3_count);
void mcp_unix_socket_server_publish_reload(struct mcp_unix_socket_server *server,
					   int success,
					   __u32 rule_count,
					   __u32 active_generation,
					   __u64 epoch,
					   const char *error);
void mcp_unix_socket_server_stop(struct mcp_unix_socket_server *server);

#endif
