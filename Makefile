# SPDX-License-Identifier: Apache-2.0
CLANG ?= clang
CC ?= cc
BPFTOOL ?= bpftool
LIBBPF_CFLAGS ?= $(shell pkg-config --cflags libbpf 2>/dev/null)
USER_LDLIBS ?= $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf) -lelf -lz

BUILD_DIR ?= build
BPF_OBJ := $(BUILD_DIR)/mcp_guard.bpf.o
BPF_SKEL := $(BUILD_DIR)/mcp_guard.skel.h
TARGET ?= mcp-guard

-include config.mk

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86 -I. -Iinclude -Ibpf
USER_CFLAGS := -g -O2 -Wall -Wextra -I. -Iinclude -I$(BUILD_DIR) $(LIBBPF_CFLAGS)

LOADER_SRCS := \
	loader/main.c \
	loader/bpf_loader.c \
	loader/policy_loader.c \
	loader/ringbuf_reader.c \
	loader/unix_socket_server.c
LOADER_OBJS := $(patsubst loader/%.c,$(BUILD_DIR)/%.o,$(LOADER_SRCS))

.PHONY: all clean distclean run unload test vmlinux \
	experiment-env experiment-preflight experiment-latency \
	experiment-hit-ratio experiment-lpm experiment-reload \
	experiment-e2e experiment-all experiment-analyze

all: $(TARGET)

vmlinux: bpf/vmlinux.h

bpf/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BUILD_DIR):
	mkdir -p $@

$(BPF_OBJ): bpf/mcp_guard.bpf.c bpf/maps.bpf.h bpf/l1_fast_path.bpf.c bpf/l2_semi_fast_path.bpf.c bpf/l3_slow_path.bpf.c include/*.h bpf/vmlinux.h | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BPF_SKEL): $(BPF_OBJ) | $(BUILD_DIR)
	$(BPFTOOL) gen skeleton $< > $@

$(BUILD_DIR)/%.o: loader/%.c loader/*.h include/*.h $(BPF_SKEL) | $(BUILD_DIR)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(TARGET): $(LOADER_OBJS)
	$(CC) $(USER_CFLAGS) $^ -o $@ $(USER_LDLIBS)

run: $(TARGET)
	sudo ./$(TARGET) policies

test: $(TARGET)
	./tests/test_execve.sh
	./tests/test_file_access.sh
	./tests/test_socket_connect.sh
	./tests/test_policy_update.sh
	./tests/test_l1_cache.sh
	./tests/test_path_lpm_trie.sh
	./tests/test_l2_flags_cache.sh
	./tests/test_metrics_snapshot.sh
	./tests/test_atomic_reload.sh
	./tests/test_agent_scope.sh

experiment-env:
	@ts=$$(date +%Y%m%d_%H%M%S); \
	dir=experiments/results/$${ts}_env; \
	mkdir -p "$${dir}"; \
	experiments/scripts/collect_env.sh "$${dir}" policies; \
	echo "$${dir}"

experiment-preflight:
	experiments/scripts/preflight_check.sh

experiment-latency:
	experiments/scripts/run_latency_benchmark.sh

experiment-hit-ratio:
	experiments/scripts/run_hit_ratio_benchmark.sh

experiment-lpm:
	experiments/scripts/run_lpm_trie_benchmark.sh

experiment-reload:
	experiments/scripts/run_reload_benchmark.sh

experiment-e2e:
	experiments/scripts/run_end_to_end_benchmark.sh

experiment-all:
	experiments/scripts/run_all.sh

experiment-analyze:
	@if [ -z "$${RESULT_DIR:-}" ]; then \
		latest=$$(find experiments/results -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1); \
	else \
		latest="$${RESULT_DIR}"; \
	fi; \
	if [ -z "$${latest}" ]; then \
		echo "no experiment result directory found" >&2; exit 1; \
	fi; \
	python3 experiments/tools/analyze_results.py "$${latest}"; \
	echo "$${latest}/report.md"

unload:
	sudo pkill -INT -x $(TARGET) || true

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

distclean: clean
	rm -f config.log config.mk config.status
	rm -rf autom4te.cache
