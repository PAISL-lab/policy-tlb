// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

struct traced_proc {
	pid_t pid;
	bool in_syscall;
};

struct counters {
	unsigned long long total;
	unsigned long long read_count;
	unsigned long long write_count;
	unsigned long long open_count;
	unsigned long long exec_count;
	unsigned long long connect_count;
};

static struct traced_proc *procs;
static size_t proc_count;
static size_t proc_cap;

static double now_sec(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (double)tv.tv_sec + ((double)tv.tv_usec / 1000000.0);
}

static struct traced_proc *find_proc(pid_t pid)
{
	for (size_t i = 0; i < proc_count; i++) {
		if (procs[i].pid == pid)
			return &procs[i];
	}
	return NULL;
}

static struct traced_proc *add_proc(pid_t pid)
{
	struct traced_proc *proc;

	proc = find_proc(pid);
	if (proc)
		return proc;

	if (proc_count == proc_cap) {
		size_t next_cap = proc_cap ? proc_cap * 2 : 16;
		struct traced_proc *next = realloc(procs, next_cap * sizeof(*next));

		if (!next)
			return NULL;
		procs = next;
		proc_cap = next_cap;
	}

	proc = &procs[proc_count++];
	proc->pid = pid;
	proc->in_syscall = false;
	return proc;
}

static void remove_proc(pid_t pid)
{
	for (size_t i = 0; i < proc_count; i++) {
		if (procs[i].pid != pid)
			continue;
		procs[i] = procs[proc_count - 1];
		proc_count--;
		return;
	}
}

static void set_options(pid_t pid)
{
	long opts = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK |
		    PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC;

	if (ptrace(PTRACE_SETOPTIONS, pid, 0, opts) != 0 && errno != ESRCH)
		fprintf(stderr, "warning: PTRACE_SETOPTIONS failed for %d: %s\n",
			pid, strerror(errno));
}

static void count_syscall(long nr, struct counters *c)
{
	c->total++;
	switch (nr) {
	case SYS_read:
		c->read_count++;
		break;
	case SYS_write:
		c->write_count++;
		break;
#ifdef SYS_open
	case SYS_open:
		c->open_count++;
		break;
#endif
	case SYS_openat:
		c->open_count++;
		break;
#ifdef SYS_openat2
	case SYS_openat2:
		c->open_count++;
		break;
#endif
	case SYS_execve:
#ifdef SYS_execveat
	case SYS_execveat:
#endif
		c->exec_count++;
		break;
	case SYS_connect:
		c->connect_count++;
		break;
	default:
		break;
	}
}

static int resume_tracee(pid_t pid, int signal_to_deliver)
{
	if (ptrace(PTRACE_SYSCALL, pid, 0, signal_to_deliver) != 0) {
		if (errno == ESRCH)
			return 0;
		fprintf(stderr, "warning: PTRACE_SYSCALL failed for %d: %s\n",
			pid, strerror(errno));
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct counters counters = {};
	double start;
	double elapsed;
	pid_t child;
	int status;
	int exit_status = 0;

	if (argc < 3 || strcmp(argv[1], "--") != 0) {
		fprintf(stderr, "usage: %s -- command [args...]\n", argv[0]);
		return 2;
	}

	start = now_sec();
	child = fork();
	if (child < 0) {
		perror("fork");
		return 1;
	}

	if (child == 0) {
		if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) {
			perror("PTRACE_TRACEME");
			_exit(127);
		}
		raise(SIGSTOP);
		execvp(argv[2], &argv[2]);
		perror("execvp");
		_exit(127);
	}

	if (waitpid(child, &status, 0) < 0) {
		perror("waitpid");
		return 1;
	}
	add_proc(child);
	set_options(child);
	resume_tracee(child, 0);

	while (proc_count > 0) {
		pid_t pid = waitpid(-1, &status, __WALL);
		struct traced_proc *proc;

		if (pid < 0) {
			if (errno == EINTR)
				continue;
			if (errno == ECHILD)
				break;
			perror("waitpid");
			exit_status = 1;
			break;
		}

		proc = find_proc(pid);
		if (!proc) {
			proc = add_proc(pid);
			set_options(pid);
		}

		if (WIFEXITED(status)) {
			if (pid == child)
				exit_status = WEXITSTATUS(status);
			remove_proc(pid);
			continue;
		}
		if (WIFSIGNALED(status)) {
			if (pid == child)
				exit_status = 128 + WTERMSIG(status);
			remove_proc(pid);
			continue;
		}
		if (!WIFSTOPPED(status)) {
			resume_tracee(pid, 0);
			continue;
		}

		if ((status >> 16) != 0) {
			unsigned long new_pid = 0;

			if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &new_pid) == 0 &&
			    new_pid) {
				add_proc((pid_t)new_pid);
				set_options((pid_t)new_pid);
				resume_tracee((pid_t)new_pid, 0);
			}
			resume_tracee(pid, 0);
			continue;
		}

		if (WSTOPSIG(status) == (SIGTRAP | 0x80)) {
			struct user_regs_struct regs;

			if (!proc) {
				resume_tracee(pid, 0);
				continue;
			}
			if (!proc->in_syscall) {
				if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == 0)
					count_syscall((long)regs.orig_rax, &counters);
				proc->in_syscall = true;
			} else {
				proc->in_syscall = false;
			}
			resume_tracee(pid, 0);
			continue;
		}

		resume_tracee(pid, WSTOPSIG(status) == SIGTRAP ? 0 : WSTOPSIG(status));
	}

	elapsed = now_sec() - start;
	printf("ptrace_summary total_syscalls=%llu read=%llu write=%llu open=%llu exec=%llu connect=%llu elapsed_sec=%.6f\n",
	       counters.total, counters.read_count, counters.write_count,
	       counters.open_count, counters.exec_count, counters.connect_count,
	       elapsed);
	free(procs);
	return exit_status;
}
