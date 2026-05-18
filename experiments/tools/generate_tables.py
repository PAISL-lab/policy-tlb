#!/usr/bin/env python3
import argparse
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("result_dir")
    args = parser.parse_args()
    script = Path(__file__).with_name("analyze_results.py")
    return subprocess.call([sys.executable, str(script), args.result_dir])


if __name__ == "__main__":
    raise SystemExit(main())
