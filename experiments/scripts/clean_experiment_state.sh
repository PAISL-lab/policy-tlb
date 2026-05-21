#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root: sudo $0" >&2
  exit 1
fi

while read -r pid args; do
  [[ -n "${pid:-}" ]] || continue
  case "${args}" in
    *"/tmp/mcpguard-exp-"*"/policies"*)
      kill -INT "${pid}" 2>/dev/null || true
      ;;
  esac
done < <(pgrep -a -x mcp-guard 2>/dev/null || true)

sleep 0.5

while read -r pid args; do
  [[ -n "${pid:-}" ]] || continue
  case "${args}" in
    *"/tmp/mcpguard-exp-"*"/policies"*)
      kill -TERM "${pid}" 2>/dev/null || true
      ;;
  esac
done < <(pgrep -a -x mcp-guard 2>/dev/null || true)

sleep 0.2

while read -r pid args; do
  [[ -n "${pid:-}" ]] || continue
  case "${args}" in
    *"/tmp/mcpguard-exp-"*"/policies"*)
      kill -KILL "${pid}" 2>/dev/null || true
      ;;
  esac
done < <(pgrep -a -x mcp-guard 2>/dev/null || true)

rm -f /tmp/mcp-guard.sock
find /tmp -maxdepth 1 -type d -name 'mcpguard-exp-*' -exec chmod -R u+rwx {} + 2>/dev/null || true
find /tmp -maxdepth 1 -type d -name 'mcpguard-exp-*' -exec rm -rf {} + 2>/dev/null || true
echo "experiment state cleaned"
