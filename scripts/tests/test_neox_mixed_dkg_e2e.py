"""Tests for the mixed-client Neo X DKG epoch gate."""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


SCRIPT = pathlib.Path(__file__).parents[1] / "neox-mixed-dkg-e2e.py"
SPEC = importlib.util.spec_from_file_location("neox_mixed_dkg_e2e", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GATE
SPEC.loader.exec_module(GATE)


def encode_uint256(value: int) -> str:
    return f"0x{value:064x}"


def encode_bytes(value: bytes) -> str:
    padding = bytes((-len(value)) % 32)
    return "0x" + (32).to_bytes(32, "big").hex() + len(value).to_bytes(32, "big").hex() + (
        value + padding
    ).hex()


class FakeNeoXRpc(BaseHTTPRequestHandler):
    round_calls = 0
    lock = threading.Lock()

    def do_POST(self) -> None:  # noqa: N802 - standard-library callback name
        length = int(self.headers["content-length"])
        request = json.loads(self.rfile.read(length))
        method = request["method"]
        if method == "eth_chainId":
            result = "0x1234"
        elif method == "eth_blockNumber":
            result = "0x5"
        elif method == "net_peerCount":
            result = "0x1"
        elif method == "eth_getBlockByNumber":
            result = {
                "hash": "0x" + "11" * 32,
                "parentHash": "0x" + "22" * 32,
                "stateRoot": "0x" + "33" * 32,
                "transactionsRoot": "0x" + "44" * 32,
                "receiptsRoot": "0x" + "55" * 32,
                "number": request["params"][0],
            }
        elif method == "eth_call":
            data = request["params"][0]["data"]
            if data == GATE.ROUND_NUMBER_CALL:
                with self.lock:
                    type(self).round_calls += 1
                    current_round = 1 if type(self).round_calls <= 2 else 2
                result = encode_uint256(current_round)
            elif data.startswith(GATE.AGGREGATED_COMMITMENTS_CALL):
                result = encode_bytes(bytes([0x66]) * GATE.AGGREGATED_COMMITMENT_BYTES)
            else:
                self.send_error(400, "unsupported contract call")
                return
        else:
            self.send_error(400, f"unsupported method {method}")
            return
        response = json.dumps(
            {"jsonrpc": "2.0", "id": request["id"], "result": result}
        ).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class MixedDkgGateTests(unittest.TestCase):
    def setUp(self) -> None:
        FakeNeoXRpc.round_calls = 0
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeNeoXRpc)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def test_decodes_strict_abi_values(self) -> None:
        self.assertEqual(GATE.decode_abi_uint256(encode_uint256(7), "round"), 7)
        payload = bytes(range(128))
        self.assertEqual(GATE.decode_abi_bytes(encode_bytes(payload), "commitment"), payload)
        with self.assertRaises(GATE.GateFailure):
            GATE.decode_abi_bytes("0x", "commitment")

    def test_reads_prometheus_counter_with_labels(self) -> None:
        payload = """
        # HELP reth_neox_dkg_replacements_total replacements
        reth_neox_dkg_replacements_total{client=\"reth\"} 3
        """
        original_urlopen = GATE.urllib.request.urlopen

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read(self):
                return payload.encode()

        try:
            GATE.urllib.request.urlopen = lambda *_args, **_kwargs: Response()
            self.assertEqual(
                GATE.read_prometheus_counter(
                    "http://metrics", GATE.DKG_REPLACEMENTS_METRIC, 1.0
                ),
                3.0,
            )
        finally:
            GATE.urllib.request.urlopen = original_urlopen

    def test_requires_metrics_for_replacement_gate(self) -> None:
        args = argparse.Namespace(
            geth=[self.url],
            expected_geth=1,
            minimum_blocks=0,
            gate_timeout=1.0,
            poll_interval=0.01,
            rpc_timeout=1.0,
            minimum_peers=1,
            max_height_skew=0,
            max_transient_errors=0,
            require_replacements=True,
            require_view_change=False,
            require_prover_attempts=False,
            min_prover_average_seconds=None,
            reth_metrics=None,
        )
        with self.assertRaisesRegex(GATE.GateFailure, "--reth-metrics"):
            GATE.validate_args(args)

    def test_runs_two_client_epoch_and_commitment_gate(self) -> None:
        args = argparse.Namespace(
            reth=self.url,
            geth=[self.url],
            expected_geth=1,
            minimum_blocks=0,
            gate_timeout=3.0,
            poll_interval=0.01,
            rpc_timeout=1.0,
            minimum_peers=1,
            max_height_skew=0,
            max_transient_errors=0,
            no_round_advance=False,
            allow_reorgs=False,
            require_reorg=False,
            require_transient_recovery=False,
            require_replacements=False,
            require_view_change=False,
            require_prover_attempts=False,
            min_prover_average_seconds=None,
            reth_metrics=None,
        )
        report = GATE.run_gate(args)
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["clients"], 2)
        self.assertEqual(report["initial_round"], 1)
        self.assertEqual(report["final_round"], 2)
        self.assertIsNotNone(report["initial_aggregate_commitment_sha256"])
        self.assertIsNotNone(report["aggregate_commitment_sha256"])

    def test_rejects_starting_round_commitment_divergence(self) -> None:
        original_parallel_map = GATE.parallel_map
        try:
            def divergent_map(clients, operation):
                if operation.__name__ == "<lambda>":
                    values = {}
                    for index, client in enumerate(clients):
                        values[client.name] = bytes([0x66 + index]) * GATE.AGGREGATED_COMMITMENT_BYTES
                    return values
                return original_parallel_map(clients, operation)

            GATE.parallel_map = divergent_map
            clients = [
                GATE.RpcClient("reth", self.url, 1.0),
                GATE.RpcClient("geth-1", self.url, 1.0),
            ]
            with self.assertRaisesRegex(GATE.GateFailure, "aggregate commitment differs"):
                GATE.verify_aggregate_commitment(clients, 1)
        finally:
            GATE.parallel_map = original_parallel_map

    def test_rejects_cross_client_chain_divergence(self) -> None:
        snapshots = {
            "reth": GATE.NodeSnapshot("reth", 1, 10, 1, 2),
            "geth-1": GATE.NodeSnapshot("geth-1", 2, 10, 1, 2),
        }
        with self.assertRaisesRegex(GATE.GateFailure, "chain ID"):
            GATE.validate_snapshots(snapshots, 1, 1, 0)

    def test_rejects_head_continuity_change_without_reorg_mode(self) -> None:
        original_verify_blocks = GATE.verify_blocks
        original_parallel_map = GATE.parallel_map
        try:
            GATE.verify_blocks = lambda _clients, _height: "0x" + "bb" * 32
            GATE.parallel_map = lambda clients, _operation: {
                client.name: {"parentHash": "0x" + "cc" * 32} for client in clients
            }
            clients = [GATE.RpcClient("reth", self.url, 1.0)]
            with self.assertRaisesRegex(GATE.GateFailure, "canonical head continuity"):
                GATE.verify_chain_progress(
                    clients,
                    6,
                    5,
                    "0x" + "aa" * 32,
                    False,
                )
        finally:
            GATE.verify_blocks = original_verify_blocks
            GATE.parallel_map = original_parallel_map

    def test_allows_and_records_head_continuity_change_in_reorg_mode(self) -> None:
        original_verify_blocks = GATE.verify_blocks
        original_parallel_map = GATE.parallel_map
        try:
            GATE.verify_blocks = lambda _clients, _height: "0x" + "bb" * 32
            GATE.parallel_map = lambda clients, _operation: {
                client.name: {"parentHash": "0x" + "cc" * 32} for client in clients
            }
            clients = [GATE.RpcClient("reth", self.url, 1.0)]
            block_hash, reorg = GATE.verify_chain_progress(
                clients,
                6,
                5,
                "0x" + "aa" * 32,
                True,
            )
            self.assertEqual(block_hash, "0x" + "bb" * 32)
            self.assertTrue(reorg)
        finally:
            GATE.verify_blocks = original_verify_blocks
            GATE.parallel_map = original_parallel_map

    def test_detects_reorg_at_anchor_after_height_jump(self) -> None:
        original_verify_blocks = GATE.verify_blocks
        original_parallel_map = GATE.parallel_map
        try:
            GATE.verify_blocks = lambda _clients, _height: "0x" + "bb" * 32

            def read_blocks(clients, operation):
                del operation
                return {
                    client.name: {
                        "hash": "0x" + "cc" * 32,
                        "parentHash": "0x" + "dd" * 32,
                    }
                    for client in clients
                }

            GATE.parallel_map = read_blocks
            clients = [GATE.RpcClient("reth", self.url, 1.0)]
            with self.assertRaisesRegex(GATE.GateFailure, "canonical head continuity"):
                GATE.verify_chain_progress(
                    clients,
                    8,
                    5,
                    "0x" + "aa" * 32,
                    False,
                )
        finally:
            GATE.verify_blocks = original_verify_blocks
            GATE.parallel_map = original_parallel_map


if __name__ == "__main__":
    unittest.main()
