"""Unit tests for the NeoX block-sync benchmark runner."""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest
from unittest import mock


SCRIPT = pathlib.Path(__file__).parents[1] / "neox-sync-benchmark.py"
SPEC = importlib.util.spec_from_file_location("neox_sync_benchmark", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
BENCH = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BENCH
SPEC.loader.exec_module(BENCH)


class SyncBenchmarkTests(unittest.TestCase):
    def valid_args(self, target_height: str = "1") -> list[str]:
        return [
            "--reth",
            "http://reth.invalid",
            "--geth",
            "http://geth.invalid",
            "--target-height",
            target_height,
            "--run-id",
            "test-run",
            "--reth-datadir",
            "/tmp/reth-test",
            "--geth-datadir",
            "/tmp/geth-test",
            "--reth-command",
            "reth node",
            "--geth-command",
            "geth",
            "--barrier-command",
            "true",
            "--reth-process-started-at",
            "2026-07-20T00:00:00Z",
            "--geth-process-started-at",
            "2026-07-20T00:00:00Z",
            "--geth-sync-target",
            "0x" + "11" * 32,
        ]

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
            BENCH.parse_args(self.valid_args("0"))

    def test_accepts_delayed_geth_sync_target(self) -> None:
        args = BENCH.parse_args(self.valid_args())
        self.assertEqual(args.geth_sync_target, "0x" + "11" * 32)

    def test_process_timestamps_are_normalized_to_utc(self) -> None:
        argv = self.valid_args()
        argv[argv.index("--reth-process-started-at") + 1] = "2026-07-20T08:00:00+08:00"
        args = BENCH.parse_args(argv)
        self.assertEqual(args.reth_process_started_at, "2026-07-20T00:00:00.000000Z")

    def test_rpc_timeout_is_recorded_pending_the_final_target_gate(self) -> None:
        future: BENCH.Future[object] = BENCH.Future()
        future.set_exception(
            BENCH.RpcResponseError(
                "geth-trigger", "debug_sync", {"code": -32002, "message": "request timed out"}
            )
        )
        outcome = BENCH.trigger_outcome(future)
        self.assertEqual(outcome["status"], "rpc_timeout_pending_target")

        rejected: BENCH.Future[object] = BENCH.Future()
        rejected.set_exception(
            BENCH.RpcResponseError(
                "geth-trigger", "debug_sync", {"code": -32001, "message": "server error"}
            )
        )
        with self.assertRaises(BENCH.RpcResponseError):
            BENCH.trigger_outcome(rejected)

    def test_transaction_stats_records_transactions_and_nonempty_blocks(self) -> None:
        class FakeClient:
            name = "reth"

            def call_batch(self, method: str, params: list[list[str]]) -> list[str]:
                self.method = method
                counts = {"0x1": "0x1", "0x2": "0x0", "0x3": "0x2"}
                return [counts[call_params[0]] for call_params in params]

        stats = BENCH.transaction_stats(FakeClient(), 0, 3, 2)
        self.assertEqual(stats, {"transactions": 3, "nonempty_blocks": 2})

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

    def test_shared_barrier_starts_both_client_timers_together(self) -> None:
        state = {"triggered": False}

        class FakeRpcClient:
            def __init__(self, name: str, url: str, timeout: float) -> None:
                self.name = name
                self.url = url
                self.timeout = timeout

            def call(
                self, method: str, params: list[object] | None = None, timeout: float | None = None
            ) -> object:
                if method == "web3_clientVersion":
                    return f"{self.name}/test"
                if method == "debug_sync":
                    return None
                if method == "eth_getBlockByNumber":
                    return {
                        "number": "0x1",
                        "hash": "0xabc",
                        "parentHash": "0xdef",
                        "stateRoot": "0x1",
                        "transactionsRoot": "0x2",
                        "receiptsRoot": "0x3",
                    }
                raise AssertionError(method)

            def quantity(self, method: str, params: list[object] | None = None) -> int:
                if method == "eth_chainId":
                    return 47763
                if method == "eth_blockNumber":
                    return int(state["triggered"])
                raise AssertionError(method)

            def call_batch(self, method: str, params: list[list[object]]) -> list[str]:
                return ["0x0"] * len(params)

        def trigger(command: str, timeout: float) -> dict[str, object]:
            state["triggered"] = True
            return {
                "started_at_utc": "2026-07-20T00:00:01Z",
                "completed_at_utc": "2026-07-20T00:00:01Z",
                "elapsed_s": 0.0,
                "exit_code": 0,
                "stdout": "",
                "stderr": "",
            }

        args = BENCH.parse_args(self.valid_args())
        with (
            mock.patch.object(BENCH, "RpcClient", FakeRpcClient),
            mock.patch.object(BENCH, "execute_barrier_command", trigger),
        ):
            report = BENCH.run(args)

        self.assertTrue(report["eligibility"]["shared_trigger_barrier"])
        self.assertLessEqual(report["eligibility"]["trigger_skew_s"], 1.0)
        self.assertEqual(report["workload"]["transactions"], 0)
        self.assertEqual(report["final_block"]["parent_hash"], "0xdef")
        self.assertEqual(report["commands"]["reth"], "reth node")
        self.assertEqual(report["timing"]["geth_trigger_rpc"]["status"], "completed")
        for event in (
            "process_started_at_utc",
            "rpc_ready_at_utc",
            "sync_triggered_at_utc",
            "completed_at_utc",
        ):
            self.assertTrue(all(report["timing"][event].values()))
        elapsed = [report["clients"][name]["elapsed_s"] for name in ("reth", "geth")]
        self.assertLess(abs(elapsed[0] - elapsed[1]), 0.05)

    def test_rejects_client_progress_before_shared_barrier(self) -> None:
        class EarlySyncRpcClient:
            def __init__(self, name: str, url: str, timeout: float) -> None:
                self.name = name
                self.url = url

            def call(
                self, method: str, params: list[object] | None = None, timeout: float | None = None
            ) -> object:
                if method == "web3_clientVersion":
                    return f"{self.name}/test"
                raise AssertionError(method)

            def quantity(self, method: str, params: list[object] | None = None) -> int:
                if method == "eth_chainId":
                    return 47763
                if method == "eth_blockNumber":
                    return 1 if self.name == "geth" else 0
                raise AssertionError(method)

        args = BENCH.parse_args(self.valid_args())
        with mock.patch.object(BENCH, "RpcClient", EarlySyncRpcClient):
            with self.assertRaisesRegex(BENCH.SyncBenchmarkError, "pre-barrier head"):
                BENCH.run(args)


if __name__ == "__main__":
    unittest.main()
