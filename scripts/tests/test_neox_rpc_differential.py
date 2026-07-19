"""Unit tests for the Neo X RPC differential helpers."""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest


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


if __name__ == "__main__":
    unittest.main()
