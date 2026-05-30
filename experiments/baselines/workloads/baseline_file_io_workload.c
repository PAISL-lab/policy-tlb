// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum workload_mode {
	MODE_WARM,
	MODE_COLD,
};

struct options {
	uint64_t events;
	uint64_t followup_per_open;
	enum workload_mode mode;
};

struct counts {
	uint64_t allow;
	uint64_t deny;
	uint64_t fail;
	uint64_t open_events;
	uint64_t read_events;
	uint64_t write_events;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [--events N] [--workload warm|cold] [--followup-per-open N]\n",
		prog);
}

static uint64_t parse_u64(const char *value, uint64_t fallback)
{
	char *end = NULL;
	unsigned long long parsed;

	if (!value || !value[0])
		return fallback;
	errno = 0;
	parsed = strtoull(value, &end, 10);
	if (errno || !end || *end)
		return fallback;
	return (uint64_t)parsed;
}

static int parse_args(int argc, char **argv, struct options *opts)
{
	static const struct option long_opts[] = {
		{ "events", required_argument, NULL, 'e' },
		{ "workload", required_argument, NULL, 'w' },
		{ "followup-per-open", required_argument, NULL, 'f' },
		{ "help", no_argument, NULL, 'h' },
		{}
	};
	int ch;

	opts->events = 10000;
	opts->followup_per_open = 10000;
	opts->mode = MODE_WARM;

	while ((ch = getopt_long(argc, argv, "e:w:f:h", long_opts, NULL)) != -1) {
		switch (ch) {
		case 'e':
			opts->events = parse_u64(optarg, opts->events);
			break;
		case 'w':
			if (strcmp(optarg, "warm") == 0)
				opts->mode = MODE_WARM;
			else if (strcmp(optarg, "cold") == 0)
				opts->mode = MODE_COLD;
			else
				return -1;
			break;
		case 'f':
			opts->followup_per_open = parse_u64(optarg, opts->followup_per_open);
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
		default:
			return -1;
		}
	}

	if (opts->events == 0)
		opts->events = 1;
	if (opts->followup_per_open == 0)
		opts->followup_per_open = 1;
	return 0;
}

static int make_temp_dir(char *buf, size_t size)
{
	int written;

	written = snprintf(buf, size, "/tmp/mcpguard-baseline-c-XXXXXX");
	if (written < 0 || (size_t)written >= size)
		return -1;
	return mkdtemp(buf) ? 0 : -1;
}

static int do_read_write(int fd, uint64_t idx, struct counts *counts)
{
	char byte = (char)('a' + (idx % 26));
	char in = 0;
	ssize_t rc;

	if (idx % 2 == 0) {
		if (lseek(fd, 0, SEEK_SET) < 0)
			return -1;
		rc = read(fd, &in, sizeof(in));
		counts->read_events++;
	} else {
		if (lseek(fd, 0, SEEK_END) < 0)
			return -1;
		rc = write(fd, &byte, sizeof(byte));
		counts->write_events++;
	}

	if (rc < 0) {
		if (errno == EACCES)
			counts->deny++;
		else
			counts->fail++;
		return -1;
	}

	counts->allow++;
	return 0;
}

static int run_warm(const struct options *opts, const char *base,
		    struct counts *counts)
{
	uint64_t remaining = opts->events;
	uint64_t group = 0;

	while (remaining > 0) {
		char path[512];
		uint64_t ops = opts->followup_per_open;
		int fd;

		if (ops > remaining)
			ops = remaining;

		snprintf(path, sizeof(path), "%s/warm_%llu.dat", base,
			 (unsigned long long)group++);
		fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
		counts->open_events++;
		if (fd < 0) {
			if (errno == EACCES)
				counts->deny++;
			else
				counts->fail++;
			return -1;
		}
		for (uint64_t i = 0; i < ops; i++)
			(void)do_read_write(fd, i, counts);

		close(fd);
		unlink(path);
		remaining -= ops;
	}

	return counts->fail ? -1 : 0;
}

static int run_cold(const struct options *opts, const char *base,
		    struct counts *counts)
{
	for (uint64_t i = 0; i < opts->events; i++) {
		char path[512];
		int fd;

		snprintf(path, sizeof(path), "%s/cold_%llu.dat", base,
			 (unsigned long long)i);
		fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
		counts->open_events++;
		if (fd < 0) {
			if (errno == EACCES)
				counts->deny++;
			else
				counts->fail++;
			continue;
		}
		(void)do_read_write(fd, i, counts);
		close(fd);
		unlink(path);
	}

	return counts->fail ? -1 : 0;
}

int main(int argc, char **argv)
{
	struct options opts;
	struct counts counts = {};
	char temp_dir[256];
	int rc;

	if (parse_args(argc, argv, &opts) != 0) {
		usage(argv[0]);
		return 2;
	}
	if (make_temp_dir(temp_dir, sizeof(temp_dir)) != 0) {
		perror("mkdtemp");
		return 1;
	}

	if (opts.mode == MODE_WARM)
		rc = run_warm(&opts, temp_dir, &counts);
	else
		rc = run_cold(&opts, temp_dir, &counts);

	rmdir(temp_dir);

	printf("workload=%s\n", opts.mode == MODE_WARM ? "file_warm" : "file_cold");
	printf("workload_impl=c\n");
	printf("events=%llu\n", (unsigned long long)opts.events);
	printf("followup_per_open=%llu\n", (unsigned long long)opts.followup_per_open);
	printf("open_events=%llu\n", (unsigned long long)counts.open_events);
	printf("file_events=%llu\n",
	       (unsigned long long)(counts.read_events + counts.write_events));
	printf("read_events=%llu\n", (unsigned long long)counts.read_events);
	printf("write_events=%llu\n", (unsigned long long)counts.write_events);
	printf("socket_events=0\n");
	printf("exec_events=0\n");
	printf("allow_count=%llu\n", (unsigned long long)counts.allow);
	printf("deny_count=%llu\n", (unsigned long long)counts.deny);
	printf("fail_count=%llu\n", (unsigned long long)counts.fail);
	return rc == 0 ? 0 : 1;
}
