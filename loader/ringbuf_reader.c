// SPDX-License-Identifier: Apache-2.0
#include "ringbuf_reader.h"

#include <errno.h>
#include <stdlib.h>

#include <bpf/libbpf.h>

struct mcp_ringbuf_reader {
	struct ring_buffer *rb;
	mcp_event_handler_fn handler;
	void *ctx;
};

static int mcp_ringbuf_dispatch(void *ctx, void *data, size_t size)
{
	struct mcp_ringbuf_reader *reader = ctx;

	if (!reader || !reader->handler)
		return 0;
	if (size < sizeof(struct mcp_event))
		return 0;

	return reader->handler(reader->ctx, data);
}

int mcp_ringbuf_reader_open(int events_fd,
			    mcp_event_handler_fn handler,
			    void *ctx,
			    struct mcp_ringbuf_reader **out)
{
	struct mcp_ringbuf_reader *reader;

	if (events_fd < 0 || !handler || !out)
		return -EINVAL;

	reader = calloc(1, sizeof(*reader));
	if (!reader)
		return -ENOMEM;

	reader->handler = handler;
	reader->ctx = ctx;
	reader->rb = ring_buffer__new(events_fd, mcp_ringbuf_dispatch, reader, NULL);
	if (!reader->rb) {
		int err = -errno;

		free(reader);
		return err;
	}

	*out = reader;
	return 0;
}

int mcp_ringbuf_reader_poll(struct mcp_ringbuf_reader *reader, int timeout_ms)
{
	if (!reader || !reader->rb)
		return -EINVAL;
	return ring_buffer__poll(reader->rb, timeout_ms);
}

void mcp_ringbuf_reader_close(struct mcp_ringbuf_reader *reader)
{
	if (!reader)
		return;
	ring_buffer__free(reader->rb);
	free(reader);
}
