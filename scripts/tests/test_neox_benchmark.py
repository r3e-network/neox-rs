"""Unit tests for the NeoX performance benchmark harness."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).parents[1] / "neox-benchmark.py"
SPEC = importlib.util.spec_from_file_location("neox_benchmark", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
BENCH = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BENCH
SPEC.loader.exec_module(BENCH)


class BenchmarkCorpusTests(unittest.TestCase):
    def test_corpus_is_deterministic_and_contains_neox_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            genesis = pathlib.Path(directory) / "genesis.json"
            genesis.write_text(
                json.dumps(
                    {
                        "alloc": {
                            "0x0000000000000000000000000000000000000001": {"balance": "0x1"},
                            "0x1212000000000000000000000000000000000000": {"code": "0x6000"},
                        }
                    }
                ),
                encoding="utf-8",
            )
            first = BENCH.build_cases(str(genesis))
            second = BENCH.build_cases(str(genesis))
        self.assertEqual(first, second)
        names = {case.name for case in first}
        self.assertIn("block_full", names)
        self.assertIn("policy_storage_7", names)
        self.assertIn("evm_call_system_impl", names)

    def test_error_probe_ignores_empty_revert_data(self) -> None:
        geth = {"jsonrpc": "2.0", "id": 1, "error": {"code": 3, "message": "execution reverted", "data": "0x"}}
        reth = {"jsonrpc": "2.0", "id": 1, "error": {"code": 3, "message": "execution reverted"}}
        self.assertEqual(BENCH.semantic_token(geth), BENCH.semantic_token(reth))

    def test_percentile_and_concurrency_parser(self) -> None:
        self.assertEqual(BENCH._percentile([1.0, 2.0, 3.0, 4.0], 0.95), 4.0)
        self.assertEqual(BENCH._parse_concurrency("1,4,16"), [1, 4, 16])
        with self.assertRaises(Exception):
            BENCH._parse_concurrency("0")


if __name__ == "__main__":
    unittest.main()
