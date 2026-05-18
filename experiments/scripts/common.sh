#!/usr/bin/env bash

mcp_exp_restore_result_owner() {
  local result_dir="${1:-}"

  [[ -n "${result_dir}" && -d "${result_dir}" ]] || return 0
  [[ "${MCP_GUARD_KEEP_ROOT_RESULTS:-0}" != "1" ]] || return 0

  if [[ "${EUID}" -eq 0 && -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]]; then
    chown -R "${SUDO_UID}:${SUDO_GID}" "${result_dir}" 2>/dev/null || true
  fi
}
