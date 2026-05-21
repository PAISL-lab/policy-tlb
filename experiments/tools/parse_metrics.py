#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import argparse
import csv
import json
import re
from pathlib import Path


METRIC_RE = re.compile(
    r"hook=(?P<hook>\S+)\s+layer=(?P<layer>\S+)\s+action=(?P<action>\S+)\s+"
    r"count=(?P<count>\d+)\s+avg_ns=(?P<avg_ns>\d+)\s+min_ns=(?P<min_ns>\d+)\s+"
    r"max_ns=(?P<max_ns>\d+)\s+buckets=\[(?P<buckets>[0-9,\s]+)\]"
)


FIELDNAMES = [
    "run_id",
    "hook",
    "layer",
    "action",
    "count",
    "avg_ns",
    "min_ns",
    "max_ns",
    "bucket_0",
    "bucket_1",
    "bucket_2",
    "bucket_3",
    "bucket_4",
    "bucket_5",
    "bucket_6",
    "bucket_7",
]


def parse_metrics(text: str, run_id: int) -> list[dict]:
    rows = []
    for line in text.splitlines():
        match = METRIC_RE.search(line)
        if not match:
            continue
        buckets = [int(part.strip()) for part in match.group("buckets").split(",")]
        while len(buckets) < 8:
            buckets.append(0)
        rows.append(
            {
                "run_id": run_id,
                "hook": match.group("hook"),
                "layer": match.group("layer"),
                "action": match.group("action"),
                "count": int(match.group("count")),
                "avg_ns": int(match.group("avg_ns")),
                "min_ns": int(match.group("min_ns")),
                "max_ns": int(match.group("max_ns")),
                "buckets": buckets[:8],
            }
        )
    return rows


def write_json(path: Path, run_id: int, rows: list[dict]) -> None:
    payload = {"run_id": run_id, "metrics": rows}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=FIELDNAMES)
        writer.writeheader()
        for row in rows:
            flat = {key: row[key] for key in FIELDNAMES if not key.startswith("bucket_")}
            for idx, value in enumerate(row["buckets"]):
                flat[f"bucket_{idx}"] = value
            writer.writerow(flat)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="guard.log or metrics.txt")
    parser.add_argument("--run-id", type=int, default=0)
    parser.add_argument("--json-out", required=True)
    parser.add_argument("--csv-out", required=True)
    args = parser.parse_args()

    input_path = Path(args.input)
    rows = parse_metrics(input_path.read_text(encoding="utf-8", errors="replace"), args.run_id)
    write_json(Path(args.json_out), args.run_id, rows)
    write_csv(Path(args.csv_out), rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
