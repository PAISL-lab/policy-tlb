#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include "../include/common.h"
#include "bpf_loader.h"
#include "policy_loader.h"
#include "ringbuf_reader.h"
#include "unix_socket_server.h"

static volatile sig_atomic_t stop_requested;
static volatile sig_atomic_t reload_requested;

struct runtime_ctx {
	struct mcp_unix_socket_server *server;
};

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

static void handle_signal(int signo)
{
	if (signo == SIGHUP)
		reload_requested = 1;
	else
		stop_requested = 1;
}

static int bump_memlock_rlimit(void)
{
	struct rlimit rlim = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim) != 0)
		return -errno;
	return 0;
}

static int print_event(void *ctx, const struct mcp_event *event)
{
	struct runtime_ctx *runtime = ctx;
	char addr[INET_ADDRSTRLEN] = "";

	if (event->family == MCP_GUARD_AF_INET && event->ipv4_addr) {
		struct in_addr in = {
			.s_addr = event->ipv4_addr,
		};

		inet_ntop(AF_INET, &in, addr, sizeof(addr));
	}

	printf("[%s] pid=%u uid=%u hook=%s rule=%u error=%u path=%s",
	       action_name(event->action), event->pid, event->uid,
	       hook_name(event->hook_id), event->rule_id, event->error,
	       event->path[0] ? event->path : "-");
	if (addr[0])
		printf(" dst=%s:%u", addr, event->port);
	if (event->rule_name[0])
		printf(" rule=%s", event->rule_name);
	printf("\n");

	if (runtime && runtime->server)
		mcp_unix_socket_server_publish(runtime->server, event);

	return 0;
}

static int load_policy_or_report(const char *policy_dir,
				 struct mcp_bpf *guard,
				 struct mcp_policy_load_result *result)
{
	int err;

	err = mcp_policy_load_dir(policy_dir,
				  mcp_bpf_map_fd(guard, MCP_BPF_MAP_POLICY_RULES),
				  mcp_bpf_map_fd(guard, MCP_BPF_MAP_POLICY_CONFIG),
				  mcp_bpf_map_fd(guard, MCP_BPF_MAP_GLOBAL_EPOCH),
				  result);
	if (err) {
		fprintf(stderr, "failed to load policies from %s: %s\n",
			policy_dir, strerror(-err));
		return err;
	}

	printf("loaded %u policy rules, epoch=%llu\n", result->rule_count,
	       (unsigned long long)result->epoch);
	return 0;
}

int main(int argc, char **argv)
{
	const char *policy_dir = argc > 1 ? argv[1] : "policies";
	struct mcp_policy_load_result policy_result = {};
	struct mcp_ringbuf_reader *reader = NULL;
	struct runtime_ctx runtime = {};
	struct mcp_bpf *guard = NULL;
	int err;

	setvbuf(stdout, NULL, _IOLBF, 0);
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
	signal(SIGHUP, handle_signal);

	err = bump_memlock_rlimit();
	if (err)
		fprintf(stderr, "warning: failed to raise memlock rlimit: %s\n",
			strerror(-err));

	err = mcp_bpf_open_load(&guard);
	if (err)
		goto out;

	err = load_policy_or_report(policy_dir, guard, &policy_result);
	if (err)
		goto out;

	err = mcp_bpf_attach(guard);
	if (err)
		goto out;

	err = mcp_unix_socket_server_start(MCP_GUARD_SOCKET_PATH, &runtime.server);
	if (err) {
		fprintf(stderr, "warning: unix socket disabled: %s\n", strerror(-err));
		err = 0;
	} else {
		printf("event socket listening at %s\n", MCP_GUARD_SOCKET_PATH);
	}

	err = mcp_ringbuf_reader_open(mcp_bpf_map_fd(guard, MCP_BPF_MAP_EVENTS),
				      print_event, &runtime, &reader);
	if (err) {
		fprintf(stderr, "failed to open ring buffer: %s\n", strerror(-err));
		goto out;
	}

	printf("mcp-guard running; send SIGHUP to reload policy, Ctrl-C to stop\n");
	while (!stop_requested) {
		if (reload_requested) {
			reload_requested = 0;
			load_policy_or_report(policy_dir, guard, &policy_result);
		}

		if (runtime.server)
			mcp_unix_socket_server_accept(runtime.server);

		err = mcp_ringbuf_reader_poll(reader, 250);
		if (err == -EINTR) {
			err = 0;
			continue;
		}
		if (err < 0) {
			fprintf(stderr, "ring buffer poll failed: %s\n", strerror(-err));
			break;
		}
		err = 0;
	}

out:
	mcp_ringbuf_reader_close(reader);
	mcp_unix_socket_server_stop(runtime.server);
	mcp_bpf_destroy(guard);
	return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
