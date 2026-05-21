#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later

mcp_exp_restore_result_owner() {
  local result_dir="${1:-}"

  [[ -n "${result_dir}" && -d "${result_dir}" ]] || return 0
  [[ "${MCP_GUARD_KEEP_ROOT_RESULTS:-0}" != "1" ]] || return 0

  if [[ "${EUID}" -eq 0 && -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]]; then
    chown -R "${SUDO_UID}:${SUDO_GID}" "${result_dir}" 2>/dev/null || true
  fi
}

mcp_exp_stop_process() {
  local pid="${1:-}"
  local grace_loops="${2:-${EXPERIMENT_GUARD_STOP_GRACE_LOOPS:-20}}"

  [[ -n "${pid}" ]] || return 0
  kill -0 "${pid}" 2>/dev/null || return 0

  kill -INT "${pid}" 2>/dev/null || true
  for _ in $(seq 1 "${grace_loops}"); do
    if ! kill -0 "${pid}" 2>/dev/null; then
      wait "${pid}" 2>/dev/null || true
      return 0
    fi
    sleep 0.1
  done

  kill -TERM "${pid}" 2>/dev/null || true
  sleep 0.2
  kill -KILL "${pid}" 2>/dev/null || true
  wait "${pid}" 2>/dev/null || true
}

mcp_exp_guard_pids_for_policy() {
  local policy_dir="${1:-}"
  local pid args

  [[ -n "${policy_dir}" ]] || return 0
  while read -r pid args; do
    [[ -n "${pid:-}" ]] || continue
    case "${args}" in
      *"mcp-guard ${policy_dir}"*|*"mcp-guard ${policy_dir}/"*|*"mcp-guard"*" ${policy_dir}"*)
        echo "${pid}"
        ;;
    esac
  done < <(pgrep -a -x mcp-guard 2>/dev/null || true)
}

mcp_exp_stop_guard_for_policy() {
  local policy_dir="${1:-}"
  local initial_pid="${2:-}"
  local pid

  mcp_exp_stop_process "${initial_pid}"
  while read -r pid; do
    mcp_exp_stop_process "${pid}"
  done < <(mcp_exp_guard_pids_for_policy "${policy_dir}")
}

mcp_exp_remove_tmpdir() {
  local tmpdir="${1:-}"

  [[ -n "${tmpdir}" && -d "${tmpdir}" ]] || return 0
  chmod -R u+rwx "${tmpdir}" 2>/dev/null || true
  rm -rf "${tmpdir}" 2>/dev/null || {
    echo "[experiment] warning: failed to remove temporary directory: ${tmpdir}" >&2
    return 0
  }
}
