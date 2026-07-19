#!/usr/bin/env python3
"""Gate a running one-Reth/six-Geth Neo X validator network across a DKG epoch."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass


KEY_MANAGEMENT_ADDRESS = "0x1212000000000000000000000000000000000008"
ROUND_NUMBER_CALL = "0x4e2786fb"
AGGREGATED_COMMITMENTS_CALL = "0x8f560076"
AGGREGATED_COMMITMENT_BYTES = 128
BLOCK_FIELDS = (
    "hash",
    "parentHash",
    "stateRoot",
    "transactionsRoot",
    "receiptsRoot",
    "number",
)


class GateFailure(RuntimeError):
    """A transport, protocol, or cross-client compatibility failure."""


class RpcFailure(GateFailure):
    """A transient JSON-RPC transport or endpoint failure."""


class RpcClient:
    def __init__(self, name: str, url: str, timeout: float) -> None:
        self.name = name
        self.url = url
        self.timeout = timeout
        self.request_id = 0

    def call(self, method: str, params: list[object] | None = None) -> object:
        self.request_id += 1
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": self.request_id,
                "method": method,
                "params": params or [],
            }
        ).encode()
        request = urllib.request.Request(
            self.url,
            data=payload,
            headers={
                "content-type": "application/json",
                "user-agent": "neox-mixed-dkg-e2e/1",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.load(response)
        except (
            urllib.error.URLError,
            TimeoutError,
            json.JSONDecodeError,
            OSError,
        ) as error:
            raise RpcFailure(f"{self.name} {method}: {error}") from error
        if not isinstance(body, dict):
            raise RpcFailure(f"{self.name} {method}: non-object JSON-RPC response")
        if "error" in body:
            raise RpcFailure(f"{self.name} {method}: {body['error']}")
        if "result" not in body:
            raise RpcFailure(f"{self.name} {method}: missing result")
        return body["result"]

    def quantity(self, method: str, params: list[object] | None = None) -> int:
        return decode_quantity(self.call(method, params), f"{self.name} {method}")

    def contract_call(self, data: str) -> str:
        value = self.call(
            "eth_call",
            [{"to": KEY_MANAGEMENT_ADDRESS, "data": data}, "latest"],
        )
        if not isinstance(value, str):
            raise GateFailure(f"{self.name} eth_call: expected hex result, got {value!r}")
        return value


@dataclass(frozen=True)
class NodeSnapshot:
    name: str
    chain_id: int
    head: int
    peers: int
    round: int


def decode_quantity(value: object, context: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise GateFailure(f"{context}: expected hex quantity, got {value!r}")
    try:
        return int(value, 16)
    except ValueError as error:
        raise GateFailure(f"{context}: invalid hex quantity {value!r}") from error


def decode_abi_uint256(value: str, context: str) -> int:
    encoded = decode_hex(value, context)
    if len(encoded) != 32:
        raise GateFailure(f"{context}: uint256 response is {len(encoded)} bytes, expected 32")
    return int.from_bytes(encoded, "big")


def decode_abi_bytes(value: str, context: str) -> bytes:
    encoded = decode_hex(value, context)
    if len(encoded) < 64 or len(encoded) % 32 != 0:
        raise GateFailure(f"{context}: malformed dynamic-bytes response length {len(encoded)}")
    offset = int.from_bytes(encoded[:32], "big")
    if offset != 32:
        raise GateFailure(f"{context}: dynamic-bytes offset is {offset}, expected 32")
    length = int.from_bytes(encoded[32:64], "big")
    padded_length = ((length + 31) // 32) * 32
    if len(encoded) != 64 + padded_length:
        raise GateFailure(
            f"{context}: encoded length {len(encoded)} does not match payload length {length}"
        )
    return encoded[64 : 64 + length]


def decode_hex(value: str, context: str) -> bytes:
    if not value.startswith("0x"):
        raise GateFailure(f"{context}: expected 0x-prefixed hex")
    try:
        return bytes.fromhex(value[2:])
    except ValueError as error:
        raise GateFailure(f"{context}: invalid hex") from error


def round_number(client: RpcClient) -> int:
    return decode_abi_uint256(client.contract_call(ROUND_NUMBER_CALL), f"{client.name} round")


def aggregate_commitment(client: RpcClient, round_value: int) -> bytes:
    call_data = f"{AGGREGATED_COMMITMENTS_CALL}{round_value:064x}"
    return decode_abi_bytes(
        client.contract_call(call_data),
        f"{client.name} aggregate commitment round {round_value}",
    )


def verify_aggregate_commitment(clients: list[RpcClient], round_value: int) -> str:
    """Require every client to expose the same deployed aggregate commitment."""

    commitments = parallel_map(
        clients, lambda client: aggregate_commitment(client, round_value)
    )
    reference = commitments[clients[0].name]
    if len(reference) != AGGREGATED_COMMITMENT_BYTES:
        raise GateFailure(
            f"round {round_value} aggregate commitment is {len(reference)} bytes, "
            f"expected {AGGREGATED_COMMITMENT_BYTES}"
        )
    for name, commitment in commitments.items():
        if commitment != reference:
            raise GateFailure(f"{name}: aggregate commitment differs at round {round_value}")
    return hashlib.sha256(reference).hexdigest()


def snapshot(client: RpcClient) -> NodeSnapshot:
    return NodeSnapshot(
        name=client.name,
        chain_id=client.quantity("eth_chainId"),
        head=client.quantity("eth_blockNumber"),
        peers=client.quantity("net_peerCount"),
        round=round_number(client),
    )


def parallel_map(clients: list[RpcClient], operation):
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(clients)) as executor:
        futures = {executor.submit(operation, client): client for client in clients}
        for future in concurrent.futures.as_completed(futures):
            client = futures[future]
            try:
                results[client.name] = future.result()
            except GateFailure:
                raise
            except Exception as error:  # pragma: no cover - defensive wrapper
                raise GateFailure(f"{client.name}: {error}") from error
    return results


def read_block(client: RpcClient, height: int) -> dict[str, object]:
    block = client.call("eth_getBlockByNumber", [hex(height), False])
    if not isinstance(block, dict):
        raise GateFailure(f"{client.name}: block {height} is unavailable")
    return block


def verify_blocks(clients: list[RpcClient], height: int) -> str:
    blocks = parallel_map(clients, lambda client: read_block(client, height))
    reference_name = clients[0].name
    reference = blocks[reference_name]
    for name, block in blocks.items():
        for field in BLOCK_FIELDS:
            if block.get(field) != reference.get(field):
                raise GateFailure(
                    f"block {height} field {field} diverges: "
                    f"{reference_name}={reference.get(field)!r}, {name}={block.get(field)!r}"
                )
    block_hash = reference.get("hash")
    if not isinstance(block_hash, str):
        raise GateFailure(f"block {height}: missing hash")
    return block_hash


def verify_chain_progress(
    clients: list[RpcClient],
    height: int,
    previous_height: int | None,
    previous_hash: str | None,
    allow_reorgs: bool,
) -> tuple[str, bool]:
    """Verify a common head and detect canonical continuity changes.

    The polling loop advances to the lowest common height.  A restart or a
    faster peer can therefore make that height jump by more than one block;
    checking only the new head would miss a reorganization at the previous
    common height.  Always re-read that anchor before checking the adjacent
    parent link.
    """

    block_hash = verify_blocks(clients, height)
    if previous_height is None or previous_hash is None:
        return block_hash, False

    reorg = False
    if height == previous_height:
        reorg = block_hash != previous_hash
    elif height > previous_height:
        anchor_blocks = parallel_map(
            clients, lambda client: read_block(client, previous_height)
        )
        anchor_hashes = {block.get("hash") for block in anchor_blocks.values()}
        reorg = anchor_hashes != {previous_hash}
        if not reorg and height == previous_height + 1:
            blocks = parallel_map(clients, lambda client: read_block(client, height))
            parent_hashes = {block.get("parentHash") for block in blocks.values()}
            reorg = parent_hashes != {previous_hash}

    if reorg and not allow_reorgs:
        raise GateFailure(
            f"canonical head continuity changed at height {height}: "
            f"previous={previous_hash}, current={block_hash}"
        )
    return block_hash, reorg


def validate_snapshots(
    snapshots: dict[str, NodeSnapshot],
    expected_chain_id: int,
    minimum_peers: int,
    max_height_skew: int,
) -> tuple[int, int, int]:
    for current in snapshots.values():
        if current.chain_id != expected_chain_id:
            raise GateFailure(
                f"{current.name}: chain ID {current.chain_id} differs from {expected_chain_id}"
            )
        if current.peers < minimum_peers:
            raise GateFailure(
                f"{current.name}: peer count {current.peers} is below {minimum_peers}"
            )
    heads = [current.head for current in snapshots.values()]
    if max(heads) - min(heads) > max_height_skew:
        raise GateFailure(
            f"height skew {max(heads) - min(heads)} exceeds {max_height_skew}: {heads}"
        )
    rounds = [current.round for current in snapshots.values()]
    if max(rounds) - min(rounds) > 1:
        raise GateFailure(f"DKG round spread exceeds one canonical transition: {rounds}")
    return min(heads), min(rounds), max(rounds)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reth", required=True, help="JSON-RPC URL of the Reth validator")
    parser.add_argument(
        "--geth",
        action="append",
        default=[],
        help="JSON-RPC URL of a Geth validator; repeat once per validator",
    )
    parser.add_argument(
        "--expected-geth",
        type=int,
        default=6,
        help="required Geth validator count (default: 6)",
    )
    parser.add_argument("--minimum-blocks", type=int, default=3)
    parser.add_argument("--gate-timeout", type=float, default=3600.0)
    parser.add_argument("--poll-interval", type=float, default=2.0)
    parser.add_argument("--rpc-timeout", type=float, default=10.0)
    parser.add_argument("--minimum-peers", type=int, default=1)
    parser.add_argument("--max-height-skew", type=int, default=3)
    parser.add_argument(
        "--max-transient-errors",
        type=int,
        default=30,
        help="RPC poll failures tolerated while nodes are intentionally restarted",
    )
    parser.add_argument(
        "--no-round-advance",
        action="store_true",
        help="only verify mixed-client block agreement; skip the DKG epoch requirement",
    )
    parser.add_argument(
        "--allow-reorgs",
        action="store_true",
        help="record a converged canonical reorganization instead of failing continuity checks",
    )
    parser.add_argument(
        "--require-reorg",
        action="store_true",
        help="require at least one converged canonical reorganization during the gate",
    )
    parser.add_argument(
        "--require-transient-recovery",
        action="store_true",
        help="require at least one tolerated RPC outage, as produced by a restart exercise",
    )
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    if len(args.geth) != args.expected_geth:
        raise GateFailure(
            f"expected {args.expected_geth} --geth endpoints, received {len(args.geth)}"
        )
    for name in (
        "expected_geth",
        "minimum_blocks",
        "minimum_peers",
        "max_height_skew",
        "max_transient_errors",
    ):
        if getattr(args, name) < 0:
            raise GateFailure(f"--{name.replace('_', '-')} cannot be negative")
    for name in ("gate_timeout", "poll_interval", "rpc_timeout"):
        if getattr(args, name) <= 0:
            raise GateFailure(f"--{name.replace('_', '-')} must be positive")


def run_gate(args: argparse.Namespace) -> dict[str, object]:
    validate_args(args)
    clients = [RpcClient("reth", args.reth, args.rpc_timeout)] + [
        RpcClient(f"geth-{index}", url, args.rpc_timeout)
        for index, url in enumerate(args.geth, start=1)
    ]
    initial = parallel_map(clients, snapshot)
    expected_chain_id = initial["reth"].chain_id
    initial_height, initial_round, maximum_round = validate_snapshots(
        initial, expected_chain_id, args.minimum_peers, args.max_height_skew
    )
    if initial_round != maximum_round:
        raise GateFailure(
            f"start the gate from a settled DKG round, observed "
            f"{[item.round for item in initial.values()]}"
        )
    initial_hash = verify_blocks(clients, initial_height)
    initial_commitment_digest = None
    if not args.no_round_advance:
        initial_commitment_digest = verify_aggregate_commitment(clients, initial_round)
    target_height = initial_height + args.minimum_blocks
    target_round = initial_round if args.no_round_advance else initial_round + 1
    deadline = time.monotonic() + args.gate_timeout
    highest_common_height = initial_height
    latest_hash = initial_hash
    reorgs_detected = 0
    transient_errors = 0
    polls = 0

    while time.monotonic() < deadline:
        polls += 1
        try:
            current = parallel_map(clients, snapshot)
            common_height, minimum_round, maximum_round = validate_snapshots(
                current, expected_chain_id, args.minimum_peers, args.max_height_skew
            )
            if common_height >= highest_common_height:
                latest_hash, reorg = verify_chain_progress(
                    clients,
                    common_height,
                    highest_common_height,
                    latest_hash,
                    args.allow_reorgs or args.require_reorg,
                )
                if reorg:
                    reorgs_detected += 1
            if common_height > highest_common_height:
                highest_common_height = common_height
            rounds_settled = minimum_round == maximum_round and minimum_round >= target_round
            if common_height >= target_height and rounds_settled:
                break
        except RpcFailure:
            transient_errors += 1
            if transient_errors > args.max_transient_errors:
                raise
        time.sleep(args.poll_interval)
    else:
        raise GateFailure(
            f"gate deadline expired at height {highest_common_height}, "
            f"target height {target_height}, target DKG round {target_round}"
        )

    if args.require_reorg and reorgs_detected == 0:
        raise GateFailure("gate completed without the required canonical reorganization")
    if args.require_transient_recovery and transient_errors == 0:
        raise GateFailure("gate completed without the required transient RPC recovery")

    final_round = minimum_round
    commitment_digest = None
    if not args.no_round_advance:
        commitment_digest = verify_aggregate_commitment(clients, final_round)

    return {
        "status": "ok",
        "clients": len(clients),
        "geth_validators": len(args.geth),
        "chain_id": expected_chain_id,
        "initial_height": initial_height,
        "final_height": highest_common_height,
        "initial_round": initial_round,
        "final_round": final_round,
        "initial_aggregate_commitment_sha256": initial_commitment_digest,
        "latest_common_block_hash": latest_hash,
        "aggregate_commitment_sha256": commitment_digest,
        "reorgs_detected": reorgs_detected,
        "polls": polls,
        "transient_rpc_errors": transient_errors,
    }


def main() -> int:
    args = parse_args()
    try:
        report = run_gate(args)
    except GateFailure as error:
        print(json.dumps({"status": "error", "error": str(error)}, indent=2))
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
