"""Unit tests for NeoX sync benchmark suite aggregation."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


SCRIPT = Path(__file__).parents[1] / "neox-sync-benchmark-suite.py"
SPEC = importlib.util.spec_from_file_location("neox_sync_benchmark_suite", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
SUITE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SUITE
SPEC.loader.exec_module(SUITE)


def raw_run(run_id: str, reth_elapsed: float, geth_elapsed: float) -> dict[str, object]:
    final_block = {
        "number": "0x4e20",
        "hash": "0xhash",
        "parent_hash": "0xparent",
        "state_root": "0xstate",
        "transactions_root": "0xtx",
        "receipts_root": "0xreceipt",
    }
    workload = {"blocks": 20000, "transactions": 205, "nonempty_blocks": 197}
    restart_client = {"head": "0x4e20", "hash_root_gate": "passed"}
    return {
        "schema": "neox-sync-benchmark/v2",
        "metadata": {"run_id": run_id},
        "eligibility": {
            "performance_eligible": True,
            "shared_trigger_barrier": True,
            "hash_root_gate": "passed",
            "transaction_count_gate": "passed",
        },
        "sync_source": {"client": "geth", "restart_validation": "passed"},
        "restart_validation": {
            "donor_offline": True,
            "clients": {"reth": restart_client, "geth": restart_client},
        },
        "workload": workload,
        "final_block": final_block,
        "clients": {
            "reth": {"elapsed_s": reth_elapsed, "client_version": "reth/test"},
            "geth": {"elapsed_s": geth_elapsed, "client_version": "geth/test"},
        },
    }


class SuiteTests(unittest.TestCase):
    def test_aggregate_reports_paired_median_and_ranges(self) -> None:
        runs = [
            (Path("run-1.json"), raw_run("run-1", 10.0, 20.0)),
            (Path("run-2.json"), raw_run("run-2", 20.0, 30.0)),
            (Path("run-3.json"), raw_run("run-3", 30.0, 33.0)),
        ]
        result = SUITE.aggregate(runs)
        source = result["by_sync_source"]["geth"]
        self.assertEqual(source["reth_elapsed_s"]["median"], 20.0)
        self.assertEqual(source["geth_elapsed_s"]["min"], 20.0)
        self.assertEqual(source["paired_geth_over_reth_ratio"]["median"], 1.5)

    def test_rejects_failed_restart_gate(self) -> None:
        run = raw_run("run-1", 10.0, 20.0)
        run["restart_validation"]["clients"]["geth"]["head"] = "0x0"
        with self.assertRaisesRegex(SUITE.SuiteError, "restart gate"):
            SUITE.aggregate([(Path("run.json"), run)] * 3)


if __name__ == "__main__":
    unittest.main()
