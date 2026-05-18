#!/usr/bin/env python3
import argparse
from pathlib import Path


def first_line(path: Path) -> str:
    if not path.exists():
        return "N/A"
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip():
            return line.strip()
    return "N/A"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("result_dir")
    args = parser.parse_args()
    env = Path(args.result_dir) / "env"
    print(f"system: {first_line(env / 'system.txt')}")
    print(f"kernel: {first_line(env / 'kernel.txt')}")
    print(f"git: {first_line(env / 'git.txt')}")
    print(f"bpf: {first_line(env / 'bpf.txt')}")
    print(f"loadavg: {first_line(env / 'loadavg.txt')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
