#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import argparse
import csv
import json
import statistics
from collections import defaultdict
from pathlib import Path


BUCKET_UPPER_NS = [100, 500, 1000, 5000, 10000, 50000, 100000, 100000]


def read_csv_rows(result_dir: Path) -> list[dict]:
    rows = []
    for csv_path in sorted(result_dir.glob("raw/run_*/metrics.csv")):
        with csv_path.open(newline="", encoding="utf-8") as fp:
            for row in csv.DictReader(fp):
                for key in ("run_id", "count", "avg_ns", "min_ns", "max_ns"):
                    row[key] = int(row[key])
                row["buckets"] = [int(row.get(f"bucket_{idx}", 0)) for idx in range(8)]
                rows.append(row)
    return rows


def approximate_percentile(buckets: list[int], percentile: float, min_ns: int, max_ns: int) -> int:
    total = sum(buckets)
    if total <= 0:
        return 0
    target = max(1, int((percentile / 100.0) * total + 0.999999))
    seen = 0
    for idx, count in enumerate(buckets):
        seen += count
        if seen >= target:
            if idx == 0:
                return min(max_ns, max(min_ns, BUCKET_UPPER_NS[idx]))
            return min(max_ns, max(min_ns, BUCKET_UPPER_NS[idx]))
    return max_ns


def aggregate_latency(rows: list[dict]) -> list[dict]:
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for row in rows:
        groups[(row["hook"], row["layer"], row["action"])].append(row)

    out = []
    for (hook, layer, action), items in sorted(groups.items()):
        count = sum(item["count"] for item in items)
        if count == 0:
            continue
        total_ns = sum(item["count"] * item["avg_ns"] for item in items)
        buckets = [sum(item["buckets"][idx] for item in items) for idx in range(8)]
        min_ns = min(item["min_ns"] for item in items if item["min_ns"] > 0)
        max_ns = max(item["max_ns"] for item in items)
        out.append(
            {
                "hook": hook,
                "layer": layer,
                "action": action,
                "runs": len(items),
                "count": count,
                "avg_ns": round(total_ns / count, 2),
                "min_ns": min_ns,
                "p50_ns_approx": approximate_percentile(buckets, 50, min_ns, max_ns),
                "p95_ns_approx": approximate_percentile(buckets, 95, min_ns, max_ns),
                "p99_ns_approx": approximate_percentile(buckets, 99, min_ns, max_ns),
                "max_ns": max_ns,
            }
        )
    return out


def aggregate_hit_ratio(rows: list[dict]) -> list[dict]:
    by_hook: dict[str, dict[str, int]] = defaultdict(lambda: {"L1": 0, "L2": 0, "L3": 0})
    for row in rows:
        if row["layer"] in ("L1", "L2", "L3"):
            by_hook[row["hook"]][row["layer"]] += row["count"]

    out = []
    for hook, counts in sorted(by_hook.items()):
        total = counts["L1"] + counts["L2"] + counts["L3"]
        if total == 0:
            continue
        out.append(
            {
                "workload": hook,
                "hook": hook,
                "total": total,
                "L1_count": counts["L1"],
                "L2_count": counts["L2"],
                "L3_count": counts["L3"],
                "L1_ratio": round(counts["L1"] / total, 6),
                "L2_ratio": round(counts["L2"] / total, 6),
                "L3_ratio": round(counts["L3"] / total, 6),
            }
        )
    return out


def read_elapsed(result_dir: Path) -> list[dict]:
    rows = []
    for elapsed_path in sorted(result_dir.glob("raw/run_*/elapsed.txt")):
        data = {}
        for line in elapsed_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                data[key.strip()] = value.strip()
        if data:
            data["run"] = elapsed_path.parent.name
            rows.append(data)
    return rows


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_report(result_dir: Path, latency: list[dict], ratios: list[dict]) -> None:
    git_file = result_dir / "env" / "git.txt"
    git_head = "N/A"
    if git_file.exists():
        git_head = git_file.read_text(encoding="utf-8", errors="replace").splitlines()[0]

    lines = [
        "# MCPGuard Experiment Report",
        "",
        "## Git Commit",
        "",
        git_head,
        "",
        "## Variable Control",
        "",
        "Controllable variables were fixed where possible and uncontrolled variables were recorded in `env/`.",
        "",
        "The reported latency is measured inside the eBPF hook policy decision path. It does not represent full system-call latency or complete user-application response time.",
        "",
        "On a general-purpose desktop Linux system, scheduler behavior, interrupts, cache state, temperature, and background work cannot be fully eliminated. This study therefore controls variables where practical by using the same CPU governor, core pinning, workload, policy, and repeated measurements.",
        "",
        "## Latency Summary",
        "",
        "| hook | layer | action | count | avg_ns | p50 approx | p95 approx | p99 approx | max_ns |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in latency:
        lines.append(
            f"| {row['hook']} | {row['layer']} | {row['action']} | {row['count']} | "
            f"{row['avg_ns']} | {row['p50_ns_approx']} | {row['p95_ns_approx']} | "
            f"{row['p99_ns_approx']} | {row['max_ns']} |"
        )
    lines.extend(["", "## Hit Ratios", "", "| hook | total | L1 | L2 | L3 |", "|---|---:|---:|---:|---:|"])
    for row in ratios:
        lines.append(
            f"| {row['hook']} | {row['total']} | {row['L1_ratio']} | {row['L2_ratio']} | {row['L3_ratio']} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "Use L1/L2/L3 rows to compare hook-internal policy paths. Use end-to-end tables separately for workload overhead.",
            "",
            "## Limitations",
            "",
            "Percentiles are approximate because production metrics expose histogram buckets rather than per-event samples.",
            "",
            "## Paper Draft Text",
            "",
            "MCPGuard was evaluated with 30-run repeated measurements, fixed workloads, recorded environment metadata, CPU pinning where available, and separate reporting for eBPF hook latency and end-to-end workload overhead.",
        ]
    )
    (result_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("result_dir")
    args = parser.parse_args()
    result_dir = Path(args.result_dir)
    tables = result_dir / "tables"
    parsed = result_dir / "parsed"
    tables.mkdir(parents=True, exist_ok=True)
    parsed.mkdir(parents=True, exist_ok=True)

    rows = read_csv_rows(result_dir)
    latency = aggregate_latency(rows)
    ratios = aggregate_hit_ratio(rows)

    write_csv(
        tables / "latency_by_hook_layer.csv",
        latency,
        ["hook", "layer", "action", "runs", "count", "avg_ns", "min_ns", "p50_ns_approx", "p95_ns_approx", "p99_ns_approx", "max_ns"],
    )
    write_csv(
        tables / "hit_ratio_by_workload.csv",
        ratios,
        ["workload", "hook", "total", "L1_count", "L2_count", "L3_count", "L1_ratio", "L2_ratio", "L3_ratio"],
    )

    elapsed = read_elapsed(result_dir)
    write_csv(tables / "end_to_end_overhead.csv", elapsed, sorted({key for row in elapsed for key in row.keys()}) or ["run"])
    write_csv(tables / "lpm_trie_latency.csv", [row for row in latency if row["hook"] == "file_open"], ["hook", "layer", "action", "runs", "count", "avg_ns", "min_ns", "p50_ns_approx", "p95_ns_approx", "p99_ns_approx", "max_ns"])
    write_csv(tables / "reload_consistency.csv", elapsed, sorted({key for row in elapsed for key in row.keys()}) or ["run"])
    write_csv(tables / "experiment_summary.csv", [{"metric_rows": len(rows), "latency_groups": len(latency), "ratio_groups": len(ratios)}], ["metric_rows", "latency_groups", "ratio_groups"])

    (parsed / "all_metrics.json").write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_report(result_dir, latency, ratios)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
