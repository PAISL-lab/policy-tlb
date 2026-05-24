#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import argparse
import csv
import json
import re
from collections import defaultdict
from pathlib import Path


METRIC_RE = re.compile(
    r"hook=(?P<hook>\S+)\s+layer=(?P<layer>\S+)\s+action=(?P<action>\S+)\s+"
    r"count=(?P<count>\d+)\s+avg_ns=(?P<avg_ns>\d+)\s+min_ns=(?P<min_ns>\d+)\s+"
    r"max_ns=(?P<max_ns>\d+)\s+buckets=\[(?P<buckets>[0-9,\s]+)\]"
)
PTRACE_RE = re.compile(
    r"ptrace_summary total_syscalls=(?P<total>\d+) read=(?P<read>\d+) "
    r"write=(?P<write>\d+) open=(?P<open>\d+) exec=(?P<exec>\d+) "
    r"connect=(?P<connect>\d+) elapsed_sec=(?P<elapsed>[0-9.]+)"
)


def parse_run_id(path: Path) -> int:
    match = re.search(r"run_(\d+)", path.name)
    return int(match.group(1)) if match else 0


def parse_elapsed(path: Path) -> dict[str, float | str]:
    text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    row: dict[str, float | str] = {"elapsed_sec": 0.0, "user_sec": 0.0, "sys_sec": 0.0, "max_rss_kb": 0.0}
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Elapsed (wall clock) time"):
            value = stripped.rsplit(":", 1)[1].strip()
            row["elapsed_raw"] = value
            row["elapsed_sec"] = time_to_seconds(value)
        elif stripped.startswith("User time (seconds):"):
            row["user_sec"] = float(stripped.split(":", 1)[1].strip())
        elif stripped.startswith("System time (seconds):"):
            row["sys_sec"] = float(stripped.split(":", 1)[1].strip())
        elif stripped.startswith("Maximum resident set size"):
            row["max_rss_kb"] = float(stripped.split(":", 1)[1].strip())
    return row


def time_to_seconds(value: str) -> float:
    parts = value.split(":")
    try:
        if len(parts) == 3:
            return int(parts[0]) * 3600 + int(parts[1]) * 60 + float(parts[2])
        if len(parts) == 2:
            return int(parts[0]) * 60 + float(parts[1])
        return float(parts[0])
    except (TypeError, ValueError):
        return 0.0


def parse_workload(path: Path) -> dict[str, int | str]:
    row: dict[str, int | str] = {}
    if not path.exists():
        return row
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line:
            continue
        key, value = line.strip().split("=", 1)
        if key in {"events", "file_events", "socket_events", "exec_events", "allow_count", "deny_count", "fail_count"}:
            try:
                row[key] = int(value)
            except ValueError:
                row[key] = 0
        elif key == "workload":
            row[key] = value
    return row


def parse_metrics(path: Path) -> list[dict]:
    rows = []
    if not path.exists():
        return rows
    text = path.read_text(encoding="utf-8", errors="replace")
    for match in METRIC_RE.finditer(text):
        buckets = [int(part.strip()) for part in match.group("buckets").split(",") if part.strip()]
        while len(buckets) < 8:
            buckets.append(0)
        rows.append(
            {
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


def approximate_percentile(buckets: list[int], percentile: float) -> int:
    bounds = [100, 500, 1000, 5000, 10000, 50000, 100000, 100000]
    total = sum(buckets)
    if total <= 0:
        return 0
    threshold = total * percentile
    seen = 0
    for idx, count in enumerate(buckets):
        seen += count
        if seen >= threshold:
            return bounds[idx]
    return bounds[-1]


def parse_ptrace(path: Path) -> dict[str, float | int]:
    text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    match = PTRACE_RE.search(text)
    if not match:
        return {}
    return {
        "total_syscalls": int(match.group("total")),
        "read": int(match.group("read")),
        "write": int(match.group("write")),
        "open": int(match.group("open")),
        "exec": int(match.group("exec")),
        "connect": int(match.group("connect")),
        "ptrace_elapsed_sec": float(match.group("elapsed")),
    }


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def collect_rows(result_dir: Path) -> tuple[list[dict], list[dict], list[dict]]:
    e2e_rows: list[dict] = []
    latency_rows: list[dict] = []
    ptrace_rows: list[dict] = []

    for mode_dir in sorted(path for path in result_dir.iterdir() if path.is_dir()):
        if mode_dir.name in {"env", "tables"}:
            continue
        mode = mode_dir.name
        for workload_dir in sorted(path for path in mode_dir.iterdir() if path.is_dir()):
            workload = workload_dir.name
            for run_dir in sorted(path for path in workload_dir.iterdir() if path.is_dir()):
                run_id = parse_run_id(run_dir)
                elapsed = parse_elapsed(run_dir / "elapsed.txt")
                workload_info = parse_workload(run_dir / "workload.log")
                exit_status = (run_dir / "exit_status.txt").read_text(encoding="utf-8", errors="replace").strip() if (run_dir / "exit_status.txt").exists() else ""
                events = int(workload_info.get("events", 0) or 0)
                elapsed_sec = float(elapsed.get("elapsed_sec", 0.0) or 0.0)
                e2e_rows.append(
                    {
                        "mode": mode,
                        "workload": workload,
                        "run_id": run_id,
                        "events": events,
                        "elapsed_sec": f"{elapsed_sec:.6f}",
                        "user_sec": f"{float(elapsed.get('user_sec', 0.0)):.6f}",
                        "sys_sec": f"{float(elapsed.get('sys_sec', 0.0)):.6f}",
                        "throughput_events_per_sec": f"{(events / elapsed_sec) if elapsed_sec else 0.0:.6f}",
                        "max_rss_kb": int(float(elapsed.get("max_rss_kb", 0.0) or 0.0)),
                        "exit_status": exit_status,
                    }
                )

                for metric in parse_metrics(run_dir / "guard.log"):
                    buckets = metric["buckets"]
                    latency_rows.append(
                        {
                            "mode": mode,
                            "workload": workload,
                            "run_id": run_id,
                            "hook": metric["hook"],
                            "layer": metric["layer"],
                            "action": metric["action"],
                            "count": metric["count"],
                            "avg_ns": metric["avg_ns"],
                            "min_ns": metric["min_ns"],
                            "p50_ns_approx": approximate_percentile(buckets, 0.50),
                            "p95_ns_approx": approximate_percentile(buckets, 0.95),
                            "p99_ns_approx": approximate_percentile(buckets, 0.99),
                            "max_ns": metric["max_ns"],
                        }
                    )

                ptrace = parse_ptrace(run_dir / "workload.log")
                if ptrace:
                    ptrace_rows.append({"mode": mode, "workload": workload, "run_id": run_id, **ptrace})

    return e2e_rows, latency_rows, ptrace_rows


def aggregate_e2e(rows: list[dict]) -> list[dict]:
    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in rows:
        grouped[(row["mode"], row["workload"])].append(row)

    no_guard_avg: dict[str, float] = {}
    for (mode, workload), group in grouped.items():
        if mode != "no_guard":
            continue
        no_guard_avg[workload] = sum(float(row["elapsed_sec"]) for row in group) / len(group)

    summary = []
    for (mode, workload), group in sorted(grouped.items()):
        avg_elapsed = sum(float(row["elapsed_sec"]) for row in group) / len(group)
        avg_events = sum(int(row["events"]) for row in group) / len(group)
        base = no_guard_avg.get(workload, 0.0)
        overhead = ((avg_elapsed - base) / base * 100.0) if base else 0.0
        summary.append(
            {
                "mode": mode,
                "workload": workload,
                "runs": len(group),
                "avg_events": f"{avg_events:.0f}",
                "avg_elapsed_sec": f"{avg_elapsed:.6f}",
                "avg_throughput_events_per_sec": f"{(avg_events / avg_elapsed) if avg_elapsed else 0.0:.6f}",
                "overhead_vs_no_guard_percent": f"{overhead:.6f}",
            }
        )
    return summary


def aggregate_latency(rows: list[dict]) -> list[dict]:
    grouped: dict[tuple[str, str, str, str, str], list[dict]] = defaultdict(list)
    for row in rows:
        grouped[(row["mode"], row["workload"], row["hook"], row["layer"], row["action"])].append(row)

    summary = []
    for key, group in sorted(grouped.items()):
        mode, workload, hook, layer, action = key
        total_count = sum(int(row["count"]) for row in group)
        weighted_avg = (
            sum(int(row["avg_ns"]) * int(row["count"]) for row in group) / total_count
            if total_count
            else 0.0
        )
        summary.append(
            {
                "mode": mode,
                "workload": workload,
                "hook": hook,
                "layer": layer,
                "action": action,
                "runs": len(group),
                "count": total_count,
                "avg_ns_weighted": f"{weighted_avg:.2f}",
                "min_ns": min(int(row["min_ns"]) for row in group),
                "p95_ns_approx_max": max(int(row["p95_ns_approx"]) for row in group),
                "p99_ns_approx_max": max(int(row["p99_ns_approx"]) for row in group),
                "max_ns": max(int(row["max_ns"]) for row in group),
            }
        )
    return summary


def write_report(result_dir: Path, e2e_summary: list[dict], latency_summary: list[dict]) -> None:
    lines = [
        "# Independent Baseline Experiment Report",
        "",
        "This report compares no guard, independent naive eBPF LSM, existing MCPGuard, and ptrace monitor modes.",
        "",
        "Hook-internal latency is parsed from BPF metrics summaries. End-to-end elapsed time is parsed separately from `/usr/bin/time -v` output.",
        "",
        "## End-to-End Summary",
        "",
        "| Mode | Workload | Runs | Avg sec | Throughput events/sec | Overhead vs no guard |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for row in e2e_summary:
        lines.append(
            f"| {row['mode']} | {row['workload']} | {row['runs']} | {row['avg_elapsed_sec']} | "
            f"{row['avg_throughput_events_per_sec']} | {row['overhead_vs_no_guard_percent']}% |"
        )

    lines.extend(
        [
            "",
            "## Hook-Internal Latency Summary",
            "",
            "| Mode | Workload | Hook | Layer | Action | Count | Weighted avg ns | Approx p95 ns | Approx p99 ns |",
            "|---|---|---|---|---|---:|---:|---:|---:|",
        ]
    )
    for row in latency_summary:
        lines.append(
            f"| {row['mode']} | {row['workload']} | {row['hook']} | {row['layer']} | {row['action']} | "
            f"{row['count']} | {row['avg_ns_weighted']} | {row['p95_ns_approx_max']} | {row['p99_ns_approx_max']} |"
        )

    lines.extend(
        [
            "",
            "## Interpretation Limits",
            "",
            "- The naive eBPF LSM baseline is independent code and intentionally does not use MCPGuard's L1 cache, L2 fast path, resource-id follow-up cache, tail-call pipeline, or epoch reuse.",
            "- The ptrace monitor is a traditional syscall tracing baseline and is not semantically equivalent to BPF LSM enforcement.",
            "- Approximate p95/p99 values are derived from coarse histogram buckets, not per-event raw tracing.",
            "- Hook-internal BPF metrics and end-to-end workload elapsed time must not be merged as the same measurement.",
            "",
        ]
    )
    (result_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("result_dir")
    args = parser.parse_args()

    result_dir = Path(args.result_dir)
    tables = result_dir / "tables"
    tables.mkdir(parents=True, exist_ok=True)

    e2e_rows, latency_rows, ptrace_rows = collect_rows(result_dir)
    e2e_summary = aggregate_e2e(e2e_rows)
    latency_summary = aggregate_latency(latency_rows)

    write_csv(
        tables / "baseline_e2e.csv",
        e2e_rows,
        [
            "mode",
            "workload",
            "run_id",
            "events",
            "elapsed_sec",
            "user_sec",
            "sys_sec",
            "throughput_events_per_sec",
            "max_rss_kb",
            "exit_status",
        ],
    )
    write_csv(
        tables / "baseline_hook_latency.csv",
        latency_rows,
        [
            "mode",
            "workload",
            "run_id",
            "hook",
            "layer",
            "action",
            "count",
            "avg_ns",
            "min_ns",
            "p50_ns_approx",
            "p95_ns_approx",
            "p99_ns_approx",
            "max_ns",
        ],
    )
    write_csv(
        tables / "baseline_syscall_monitor.csv",
        ptrace_rows,
        ["mode", "workload", "run_id", "total_syscalls", "read", "write", "open", "exec", "connect", "ptrace_elapsed_sec"],
    )
    write_csv(
        tables / "baseline_summary.csv",
        e2e_summary,
        [
            "mode",
            "workload",
            "runs",
            "avg_events",
            "avg_elapsed_sec",
            "avg_throughput_events_per_sec",
            "overhead_vs_no_guard_percent",
        ],
    )
    write_csv(
        tables / "baseline_latency_summary.csv",
        latency_summary,
        [
            "mode",
            "workload",
            "hook",
            "layer",
            "action",
            "runs",
            "count",
            "avg_ns_weighted",
            "min_ns",
            "p95_ns_approx_max",
            "p99_ns_approx_max",
            "max_ns",
        ],
    )
    (tables / "baseline_raw.json").write_text(
        json.dumps({"e2e": e2e_rows, "latency": latency_rows, "ptrace": ptrace_rows}, indent=2) + "\n",
        encoding="utf-8",
    )
    write_report(result_dir, e2e_summary, latency_summary)
    print(result_dir / "report.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
