#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
BUILD_DIR="${REPO_ROOT}/experiments/baselines/build/naive_ebpf_lsm"

CLANG="${CLANG:-clang}"
CC="${CC:-cc}"
BPFTOOL="${BPFTOOL:-bpftool}"
LIBBPF_CFLAGS="${LIBBPF_CFLAGS:-$(pkg-config --cflags libbpf 2>/dev/null || true)}"
USER_LDLIBS="${USER_LDLIBS:-$(pkg-config --libs libbpf 2>/dev/null || echo -lbpf) -lelf -lz}"

mkdir -p "${BUILD_DIR}"

"${CLANG}" -g -O2 -target bpf -D__TARGET_ARCH_x86 \
  -I"${REPO_ROOT}" -I"${REPO_ROOT}/include" -I"${REPO_ROOT}/bpf" ${LIBBPF_CFLAGS} \
  -c "${SCRIPT_DIR}/naive_guard.bpf.c" \
  -o "${BUILD_DIR}/naive_guard.bpf.o"

"${BPFTOOL}" gen skeleton "${BUILD_DIR}/naive_guard.bpf.o" \
  > "${BUILD_DIR}/naive_guard.skel.h"

"${CC}" -g -O2 -Wall -Wextra \
  -I"${REPO_ROOT}" -I"${REPO_ROOT}/include" -I"${BUILD_DIR}" ${LIBBPF_CFLAGS} \
  "${SCRIPT_DIR}/naive_guard_loader.c" \
  -o "${BUILD_DIR}/naive_guard_loader" ${USER_LDLIBS}

echo "${BUILD_DIR}/naive_guard_loader"
