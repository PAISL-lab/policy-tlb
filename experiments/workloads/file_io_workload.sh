#!/usr/bin/env bash
set -euo pipefail

mode="${1:-mixed}"
events="${2:-10000}"
workdir="${3:-}"
files="${4:-1}"
cache_mode="${5:-warm}"

if [[ -z "${workdir}" ]]; then
  workdir="$(mktemp -d "${TMPDIR:-/tmp}/mcpguard-exp-file-XXXXXX")"
  cleanup_workdir=1
else
  mkdir -p "${workdir}"
  cleanup_workdir=0
fi

cleanup() {
  if [[ "${cleanup_workdir}" -eq 1 ]]; then
    rm -rf "${workdir}"
  fi
}
trap cleanup EXIT

mkdir -p "${workdir}/files"
for i in $(seq 1 "${files}"); do
  printf 'mcpguard workload file %s\n' "${i}" >"${workdir}/files/file_${i}.txt"
done

python3 - "${mode}" "${events}" "${workdir}" "${files}" "${cache_mode}" <<'PY'
import os
import sys
from pathlib import Path

mode = sys.argv[1]
events = int(sys.argv[2])
workdir = Path(sys.argv[3])
files = int(sys.argv[4])
cache_mode = sys.argv[5]
file_dir = workdir / "files"

def path_for(idx: int) -> Path:
    return file_dir / f"file_{(idx % files) + 1}.txt"

def run_open(count: int) -> None:
    for idx in range(count):
        path = path_for(idx)
        if cache_mode == "cold":
            path = file_dir / f"cold_{idx}.txt"
            path.write_text(f"cold {idx}\n", encoding="utf-8")
        fd = os.open(path, os.O_RDONLY)
        os.close(fd)

def run_read(count: int) -> None:
    for idx in range(count):
        fd = os.open(path_for(idx), os.O_RDONLY)
        try:
            os.read(fd, 64)
        finally:
            os.close(fd)

def run_write(count: int) -> None:
    payload = b"x\n"
    for idx in range(count):
        fd = os.open(path_for(idx), os.O_WRONLY | os.O_APPEND)
        try:
            os.write(fd, payload)
        finally:
            os.close(fd)

if mode == "open":
    run_open(events)
elif mode == "read":
    run_read(events)
elif mode == "write":
    run_write(events)
elif mode == "mixed":
    third = max(1, events // 3)
    run_open(third)
    run_read(third)
    run_write(third)
elif mode == "all":
    run_open(events)
    run_read(events)
    run_write(events)
else:
    print("usage: file_io_workload.sh {open|read|write|mixed|all} [events] [workdir] [files] [warm|cold]", file=sys.stderr)
    raise SystemExit(2)
PY
