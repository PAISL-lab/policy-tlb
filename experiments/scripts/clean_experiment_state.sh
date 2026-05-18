#!/usr/bin/env bash
set -euo pipefail

pkill -INT -x mcp-guard 2>/dev/null || true
rm -f /tmp/mcp-guard.sock
find /tmp -maxdepth 1 -type d -name 'mcpguard-exp-*' -mtime +1 -exec rm -rf {} + 2>/dev/null || true
echo "experiment state cleaned"
