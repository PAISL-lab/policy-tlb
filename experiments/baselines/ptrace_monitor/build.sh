#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
BUILD_DIR="${REPO_ROOT}/experiments/baselines/build/ptrace_monitor"
CC="${CC:-cc}"

mkdir -p "${BUILD_DIR}"
"${CC}" -g -O2 -Wall -Wextra "${SCRIPT_DIR}/ptrace_monitor.c" \
  -o "${BUILD_DIR}/ptrace_monitor"

echo "${BUILD_DIR}/ptrace_monitor"
