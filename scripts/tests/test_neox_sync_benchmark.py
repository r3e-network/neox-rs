"""Unit tests for the NeoX block-sync benchmark runner."""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest


SCRIPT = pathlib.Path(__file__).parents[1] / "neox-sync-benchmark.py"
SPEC = importlib.util.spec_from_file_location("neox_sync_benchmark", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
BENCH = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BENCH
SPEC.loader.exec_module(BENCH)


class SyncBenchmarkTests(unittest.TestCase):
    def test_client_result_reports_block_rate(self) -> None:
        run = BENCH.ClientRun(BENCH.RpcClient("reth", "http://example.invalid", 1.0))
        run.version = "reth/test"
        run.chain_id = 47763
        run.start_head = 0
        run.end_head = 100
        run.started_at = 10.0
        run.reached_at = 12.0
        result = run.result(0, 100)
        self.assertEqual(result["imported_blocks"], 100)
        self.assertEqual(result["blocks_per_second"], 50.0)

    def test_rejects_target_at_or_before_start(self) -> None:
        with self.assertRaises(SystemExit):
            BENCH.parse_args(["--reth", "r", "--geth", "g", "--target-height", "0"])

    def test_accepts_delayed_geth_sync_target(self) -> None:
        args = BENCH.parse_args(
            [
                "--reth",
                "r",
                "--geth",
                "g",
                "--target-height",
                "1",
                "--geth-sync-target",
                "0x" + "11" * 32,
            ]
        )
        self.assertEqual(args.geth_sync_target, "0x" + "11" * 32)

    def test_final_block_verification_detects_root_mismatch(self) -> None:
        class FakeClient:
            def __init__(self, name: str, state_root: str) -> None:
                self.name = name
                self.state_root = state_root

            def call(self, method: str, params: list[object]) -> dict[str, str]:
                return {
                    "number": "0x1",
                    "hash": "0xabc",
                    "parentHash": "0xdef",
                    "stateRoot": self.state_root,
                    "transactionsRoot": "0x0",
                    "receiptsRoot": "0x0",
                }

        reth = BENCH.ClientRun(FakeClient("reth", "0x1"))
        geth = BENCH.ClientRun(FakeClient("geth", "0x2"))
        with self.assertRaisesRegex(BENCH.SyncBenchmarkError, "final block mismatch"):
            BENCH.verify_final_blocks([reth, geth], 1)


if __name__ == "__main__":
    unittest.main()
