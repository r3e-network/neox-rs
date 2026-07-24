"""Unit tests for the all-height Neo X RPC differential gate."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import pathlib
import sys
import unittest
from unittest import mock


SCRIPT = pathlib.Path(__file__).parents[1] / "neox-full-differential.py"
SPEC = importlib.util.spec_from_file_location("neox_full_differential", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
FULL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = FULL
SPEC.loader.exec_module(FULL)


class _FakeClient:
    def __init__(self, _url: str, _timeout: float) -> None:
        self.calls: list[str] = []

    def call(self, method: str, params: list[object] | None = None) -> object:
        self.calls.append(method)
        if method == "eth_blockNumber":
            return "0x1"
        if method == "eth_chainId":
            return "0x1234"
        if method == "eth_getBlockTransactionCountByNumber":
            return "0x1" if params == ["0x1"] else "0x0"
        if method == "eth_getBlockByNumber":
            height, full = params
            if height == "0x1":
                block = {field: "0x0" for field in FULL.DIFF.BLOCK_FIELDS}
                block["transactions"] = (
                    [
                        {
                            field: "0x0"
                            for field in FULL.DIFF.TRANSACTION_FIELDS
                        }
                    ]
                    if full
                    else ["0xtx"]
                )
                return block
            block = {field: "0x0" for field in FULL.DIFF.BLOCK_FIELDS}
            block["transactions"] = []
            return block
        if method == "eth_getTransactionReceipt":
            return {field: "0x0" for field in FULL.DIFF.RECEIPT_FIELDS}
        raise AssertionError(f"unexpected RPC method {method}")


class FullDifferentialTests(unittest.TestCase):
    def test_compares_receipts_only_against_references(self) -> None:
        output = io.StringIO()
        argv = [
            "neox-full-differential.py",
            "--local",
            "local",
            "--reference",
            "reference-a",
            "--reference",
            "reference-b",
            "--progress-every",
            "0",
        ]
        with mock.patch.object(FULL.DIFF, "RpcClient", _FakeClient):
            with mock.patch.object(sys, "argv", argv):
                with contextlib.redirect_stdout(output):
                    exit_code = FULL.main()
        report = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(report["blocks_checked"], 2)
        self.assertEqual(report["transactions_checked"], 1)
        self.assertEqual(report["receipt_comparisons"], 2)
        self.assertEqual(report["receipt_status_counts"], {"0x0": 1})
        self.assertEqual(report["mismatches"], [])


if __name__ == "__main__":
    unittest.main()
