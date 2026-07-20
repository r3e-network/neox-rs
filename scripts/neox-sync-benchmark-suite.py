#!/usr/bin/env python3
"""Validate and aggregate performance-eligible NeoX sync benchmark runs."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import statistics
import sys
from typing import Any


class SuiteError(RuntimeError):
    """Raised when raw runs cannot support a benchmark suite."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def metric_summary(values: list[float]) -> dict[str, float]:
    return {
        "median": round(statistics.median(values), 6),
        "min": round(min(values), 6),
        "max": round(max(values), 6),
    }


def validate_run(path: Path, run: dict[str, Any]) -> None:
    if run.get("schema") != "neox-sync-benchmark/v2":
        raise SuiteError(f"{path}: unsupported schema {run.get('schema')!r}")
    eligibility = run.get("eligibility", {})
    expected_gates = {
        "performance_eligible": True,
        "shared_trigger_barrier": True,
        "hash_root_gate": "passed",
        "transaction_count_gate": "passed",
    }
    for field, expected in expected_gates.items():
        if eligibility.get(field) != expected:
            raise SuiteError(f"{path}: eligibility gate {field} did not pass")
    source = run.get("sync_source", {})
    if source.get("client") not in {"reth", "geth"}:
        raise SuiteError(f"{path}: sync source client is missing")
    if source.get("restart_validation") != "passed":
        raise SuiteError(f"{path}: sync source restart gate did not pass")
    restart = run.get("restart_validation", {})
    if not restart.get("donor_offline"):
        raise SuiteError(f"{path}: client restart was not isolated from the donor")
    for client in ("reth", "geth"):
        result = restart.get("clients", {}).get(client, {})
        if result.get("head") != "0x4e20" or result.get("hash_root_gate") != "passed":
            raise SuiteError(f"{path}: {client} restart gate did not pass")


def aggregate(raw_runs: list[tuple[Path, dict[str, Any]]]) -> dict[str, Any]:
    if len(raw_runs) < 3:
        raise SuiteError("at least three raw runs are required")
    for path, run in raw_runs:
        validate_run(path, run)

    baseline_workload = raw_runs[0][1]["workload"]
    baseline_final = raw_runs[0][1]["final_block"]
    final_fields = (
        "number",
        "hash",
        "parent_hash",
        "state_root",
        "transactions_root",
        "receipts_root",
    )
    for path, run in raw_runs[1:]:
        if run["workload"] != baseline_workload:
            raise SuiteError(f"{path}: workload differs from the first run")
        if any(run["final_block"].get(field) != baseline_final.get(field) for field in final_fields):
            raise SuiteError(f"{path}: final block differs from the first run")

    groups: dict[str, list[tuple[Path, dict[str, Any]]]] = {}
    paired_runs: list[dict[str, Any]] = []
    for path, run in raw_runs:
        source = run["sync_source"]["client"]
        groups.setdefault(source, []).append((path, run))
        reth_elapsed = float(run["clients"]["reth"]["elapsed_s"])
        geth_elapsed = float(run["clients"]["geth"]["elapsed_s"])
        ratio = geth_elapsed / reth_elapsed
        paired_runs.append(
            {
                "run_id": run["metadata"]["run_id"],
                "source_client": source,
                "raw_file": str(path),
                "reth_elapsed_s": round(reth_elapsed, 6),
                "geth_elapsed_s": round(geth_elapsed, 6),
                "geth_over_reth_elapsed_ratio": round(ratio, 6),
                "reth_elapsed_reduction_pct": round((1.0 - reth_elapsed / geth_elapsed) * 100, 3),
                "reth_throughput_uplift_pct": round((ratio - 1.0) * 100, 3),
            }
        )

    by_source: dict[str, Any] = {}
    for source, group in sorted(groups.items()):
        if len(group) < 3:
            raise SuiteError(f"sync source {source!r} has only {len(group)} runs; need at least 3")
        reth_values = [float(run["clients"]["reth"]["elapsed_s"]) for _, run in group]
        geth_values = [float(run["clients"]["geth"]["elapsed_s"]) for _, run in group]
        ratios = [geth / reth for reth, geth in zip(reth_values, geth_values, strict=True)]
        reductions = [(1.0 - reth / geth) * 100 for reth, geth in zip(reth_values, geth_values, strict=True)]
        by_source[source] = {
            "runs": len(group),
            "reth_elapsed_s": metric_summary(reth_values),
            "geth_elapsed_s": metric_summary(geth_values),
            "paired_geth_over_reth_ratio": metric_summary(ratios),
            "paired_reth_elapsed_reduction_pct": metric_summary(reductions),
        }

    all_ratios = [run["geth_over_reth_elapsed_ratio"] for run in paired_runs]
    all_reductions = [run["reth_elapsed_reduction_pct"] for run in paired_runs]
    return {
        "schema": "neox-sync-benchmark-suite/v1",
        "generated_at_utc": utc_now(),
        "eligibility": {
            "performance_eligible": True,
            "raw_runs": len(raw_runs),
            "minimum_runs_per_source": 3,
            "all_hash_root_gates": "passed",
            "all_transaction_count_gates": "passed",
            "all_restart_gates": "passed",
        },
        "workload": baseline_workload,
        "final_block": {field: baseline_final[field] for field in final_fields},
        "clients": {
            "reth": raw_runs[0][1]["clients"]["reth"]["client_version"],
            "geth": raw_runs[0][1]["clients"]["geth"]["client_version"],
        },
        "by_sync_source": by_source,
        "all_sources": {
            "paired_geth_over_reth_ratio": metric_summary(all_ratios),
            "paired_reth_elapsed_reduction_pct": metric_summary(all_reductions),
        },
        "runs": paired_runs,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runs", nargs="+", type=Path)
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        raw_runs = [(path, json.loads(path.read_text(encoding="utf-8"))) for path in args.runs]
        suite = aggregate(raw_runs)
    except (OSError, json.JSONDecodeError, KeyError, SuiteError, ValueError) as error:
        print(f"neox-sync-benchmark-suite: {error}", file=sys.stderr)
        return 2
    encoded = json.dumps(suite, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
