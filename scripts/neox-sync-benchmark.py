#!/usr/bin/env python3
"""Measure NeoX block-sync/import time for two already-configured nodes.

The producer chain must be held at ``--target-height`` (or higher) and both
clients must start from the same ``--start-height``.  This runner deliberately
does not generate blocks: it observes two fresh nodes while they import the
same canonical block range from a running NeoX peer, then verifies the final
block hash and execution roots.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class SyncBenchmarkError(RuntimeError):
    """Raised when a sync benchmark cannot establish a fair comparison."""


class RpcFailure(SyncBenchmarkError):
    """Raised for an endpoint that is not ready yet or transiently unavailable."""


class RpcClient:
    def __init__(self, name: str, url: str, timeout: float) -> None:
        self.name = name
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.request_id = 0

    def call(self, method: str, params: list[Any] | None = None) -> Any:
        self.request_id += 1
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": self.request_id,
                "method": method,
                "params": params or [],
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            self.url,
            data=payload,
            headers={"content-type": "application/json", "user-agent": "neox-sync-benchmark/1"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.load(response)
        except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            raise RpcFailure(f"{self.name} {method}: {error}") from error
        if not isinstance(body, dict):
            raise SyncBenchmarkError(f"{self.name} {method}: non-object JSON-RPC response")
        if "error" in body:
            raise SyncBenchmarkError(f"{self.name} {method}: {body['error']}")
        if "result" not in body:
            raise SyncBenchmarkError(f"{self.name} {method}: missing result")
        return body["result"]

    def quantity(self, method: str, params: list[Any] | None = None) -> int:
        value = self.call(method, params)
        if not isinstance(value, str) or not value.startswith("0x"):
            raise SyncBenchmarkError(f"{self.name} {method}: expected hex quantity, got {value!r}")
        try:
            return int(value, 16)
        except ValueError as error:
            raise SyncBenchmarkError(f"{self.name} {method}: invalid quantity {value!r}") from error


@dataclass
class ClientRun:
    client: RpcClient
    version: str | None = None
    chain_id: int | None = None
    start_head: int | None = None
    end_head: int | None = None
    started_at: float | None = None
    reached_at: float | None = None
    samples: int = 0
    transient_errors: int = 0

    def result(self, start_height: int, target_height: int) -> dict[str, Any]:
        if self.started_at is None or self.reached_at is None:
            raise SyncBenchmarkError(f"{self.client.name}: target was not reached")
        elapsed = self.reached_at - self.started_at
        imported = target_height - start_height
        return {
            "url": self.client.url,
            "client_version": self.version,
            "chain_id": self.chain_id,
            "start_height": self.start_head,
            "target_height": target_height,
            "end_height": self.end_head,
            "imported_blocks": imported,
            "elapsed_s": round(elapsed, 6),
            "blocks_per_second": round(imported / max(elapsed, 1e-9), 3),
            "samples": self.samples,
            "transient_errors": self.transient_errors,
        }


def read_head(client: RpcClient) -> int:
    return client.quantity("eth_blockNumber")


def final_block(client: RpcClient, height: int) -> dict[str, Any]:
    block = client.call("eth_getBlockByNumber", [hex(height), False])
    if not isinstance(block, dict):
        raise SyncBenchmarkError(f"{client.name}: block {height} is unavailable")
    return block


def verify_final_blocks(runs: list[ClientRun], target_height: int) -> dict[str, Any]:
    blocks = {run.client.name: final_block(run.client, target_height) for run in runs}
    fields = ("number", "hash", "parentHash", "stateRoot", "transactionsRoot", "receiptsRoot")
    reference = blocks[runs[0].client.name]
    mismatches: list[dict[str, Any]] = []
    for name, block in blocks.items():
        for field in fields:
            if block.get(field) != reference.get(field):
                mismatches.append(
                    {
                        "client": name,
                        "field": field,
                        "reference": reference.get(field),
                        "actual": block.get(field),
                    }
                )
    if mismatches:
        raise SyncBenchmarkError(f"final block mismatch: {mismatches}")
    return {
        "height": target_height,
        "hash": reference.get("hash"),
        "state_root": reference.get("stateRoot"),
        "transactions_root": reference.get("transactionsRoot"),
        "receipts_root": reference.get("receiptsRoot"),
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reth", required=True, help="neox-rs JSON-RPC URL")
    parser.add_argument("--geth", required=True, help="Neo X Geth JSON-RPC URL")
    parser.add_argument("--start-height", type=int, default=0)
    parser.add_argument("--target-height", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--poll-interval", type=float, default=0.1)
    parser.add_argument("--deadline", type=float, default=300.0)
    parser.add_argument("--output", help="write JSON result to this path")
    args = parser.parse_args(argv)
    if args.start_height < 0:
        parser.error("--start-height cannot be negative")
    if args.target_height <= args.start_height:
        parser.error("--target-height must be greater than --start-height")
    if args.timeout <= 0 or args.poll_interval <= 0 or args.deadline <= 0:
        parser.error("timeout, poll interval, and deadline must be positive")
    return args


def run(args: argparse.Namespace) -> dict[str, Any]:
    clients = [
        ClientRun(RpcClient("reth", args.reth, args.timeout)),
        ClientRun(RpcClient("geth", args.geth, args.timeout)),
    ]
    expected_chain_id: int | None = None
    deadline = time.monotonic() + args.deadline
    while time.monotonic() < deadline and any(run.reached_at is None for run in clients):
        for current in clients:
            if current.reached_at is not None:
                continue
            try:
                if current.version is None:
                    current.version = str(current.client.call("web3_clientVersion"))
                    current.chain_id = current.client.quantity("eth_chainId")
                    if expected_chain_id is None:
                        expected_chain_id = current.chain_id
                    elif current.chain_id != expected_chain_id:
                        raise SyncBenchmarkError(
                            f"chain ID mismatch: {current.client.name}={current.chain_id}, "
                            f"expected={expected_chain_id}"
                        )
                head = read_head(current.client)
                current.samples += 1
                if current.started_at is None:
                    if head > args.start_height:
                        raise SyncBenchmarkError(
                            f"{current.client.name}: first observed head {head} exceeds "
                            f"start height {args.start_height}; reset the node before timing"
                        )
                    current.start_head = head
                    current.started_at = time.perf_counter()
                if head >= args.target_height:
                    current.end_head = head
                    current.reached_at = time.perf_counter()
            except RpcFailure:
                # Before an endpoint is ready, transport errors are expected.
                if current.started_at is None:
                    current.transient_errors += 1
                    continue
                raise
        if any(current.reached_at is None for current in clients):
            time.sleep(args.poll_interval)
    if any(current.reached_at is None for current in clients):
        pending = [current.client.name for current in clients if current.reached_at is None]
        raise SyncBenchmarkError(f"deadline expired before target {args.target_height}: {pending}")

    final = verify_final_blocks(clients, args.target_height)
    return {
        "schema": "neox-sync-benchmark/v1",
        "metadata": {
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "parameters": {
            "start_height": args.start_height,
            "target_height": args.target_height,
            "poll_interval": args.poll_interval,
        },
        "final_block": final,
        "clients": {
            current.client.name: current.result(args.start_height, args.target_height)
            for current in clients
        },
    }


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = run(args)
    except SyncBenchmarkError as error:
        print(f"neox-sync-benchmark: {error}", file=sys.stderr)
        return 2
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
