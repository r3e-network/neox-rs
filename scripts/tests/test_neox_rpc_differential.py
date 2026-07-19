"""Unit tests for the Neo X RPC differential helpers."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import pathlib
import sys
import unittest
from unittest import mock


SCRIPT = pathlib.Path(__file__).parents[1] / "neox-rpc-differential.py"
SPEC = importlib.util.spec_from_file_location("neox_rpc_differential", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
DIFF = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = DIFF
SPEC.loader.exec_module(DIFF)


class RpcDifferentialTests(unittest.TestCase):
    def test_bounds_block_transaction_hashes(self) -> None:
        block = {"transactions": ["0x1", "0x2", "0x3"]}
        self.assertEqual(DIFF.block_transaction_hashes(block, 2), ["0x1", "0x2"])

    def test_rejects_full_transaction_objects(self) -> None:
        with self.assertRaisesRegex(DIFF.RpcFailure, "requires.*hashes"):
            DIFF.block_transaction_hashes({"transactions": [{"hash": "0x1"}]}, 1)

    def test_compares_only_known_rpc_fields(self) -> None:
        mismatches = []
        DIFF.compare_rpc_object(
            mismatches,
            "transaction",
            "0x1",
            {"hash": "0x1", "unknown": "local"},
            {"hash": "0x1", "unknown": "reference"},
            ["hash"],
        )
        self.assertEqual(mismatches, [])


class _FakeClient:
    """Records calls and answers deterministically for the differential main loop."""

    def __init__(self, head: int) -> None:
        self.head = head
        self.calls: list[str] = []

    def call(self, method: str, params: object = None) -> object:
        self.calls.append(method)
        if method == "eth_blockNumber":
            return hex(self.head)
        if method == "eth_chainId":
            return "0xba93"
        if method == "eth_getBlockByNumber":
            # Identical block fields on both endpoints -> no block mismatch.
            return {field: "0x0" for field in DIFF.BLOCK_FIELDS}
        if method in ("eth_gasPrice", "eth_envelopeFee", "eth_maxEnvelopeGas"):
            # Head-dependent; only reached when both endpoints share the head.
            return "0x1"
        if method == "eth_getStorageAt":
            return "0x0"
        if method == "eth_getCode":
            return "0xabcd"
        raise AssertionError(f"unexpected method {method}")


def _run_main(local_head: int, reference_head: int) -> tuple[dict, _FakeClient, int]:
    local = _FakeClient(local_head)
    reference = _FakeClient(reference_head)
    clients = {"local": local, "reference": reference}
    argv = [
        "neox-rpc-differential.py",
        "--local",
        "local",
        "--reference",
        "reference",
        "--max-height-skew",
        "1000000",
    ]
    buffer = io.StringIO()
    with mock.patch.object(DIFF, "RpcClient", side_effect=lambda url, _timeout: clients[url]):
        with mock.patch.object(sys, "argv", argv):
            with contextlib.redirect_stdout(buffer):
                exit_code = DIFF.main()
    return json.loads(buffer.getvalue()), local, reference, exit_code


class RpcDifferentialGatingTests(unittest.TestCase):
    def test_skips_head_only_policy_rpc_across_a_height_skew(self) -> None:
        report, local, reference, exit_code = _run_main(100, 105)
        # No spurious mismatch, and the head-only methods are recorded as skipped, not called.
        self.assertEqual(report["mismatches"], [])
        self.assertEqual(exit_code, 0)
        self.assertEqual(len(report["skipped"]), 1)
        self.assertEqual(report["skipped"][0]["category"], "policy_rpc")
        self.assertNotIn("eth_gasPrice", local.calls)
        self.assertNotIn("eth_gasPrice", reference.calls)

    def test_compares_head_only_policy_rpc_at_shared_head(self) -> None:
        report, local, _reference, exit_code = _run_main(100, 100)
        # At a shared head the head-only methods are compared, not skipped.
        self.assertEqual(report["mismatches"], [])
        self.assertEqual(exit_code, 0)
        self.assertEqual(report["skipped"], [])
        self.assertIn("eth_gasPrice", local.calls)


if __name__ == "__main__":
    unittest.main()
