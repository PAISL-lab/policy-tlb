// SPDX-License-Identifier: Apache-2.0
#ifndef MCP_GUARD_RINGBUF_READER_H
#define MCP_GUARD_RINGBUF_READER_H

#include "../include/event.h"

struct mcp_ringbuf_reader;

typedef int (*mcp_event_handler_fn)(void *ctx, const struct mcp_event *event);

int mcp_ringbuf_reader_open(int events_fd,
			    mcp_event_handler_fn handler,
			    void *ctx,
			    struct mcp_ringbuf_reader **out);
int mcp_ringbuf_reader_poll(struct mcp_ringbuf_reader *reader, int timeout_ms);
void mcp_ringbuf_reader_close(struct mcp_ringbuf_reader *reader);

#endif
