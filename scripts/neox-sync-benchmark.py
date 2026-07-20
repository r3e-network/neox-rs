#!/usr/bin/env python3
"""Measure NeoX block-sync/import time behind one explicit trigger barrier.

Both fresh clients must be held at ``--start-height`` with their shared sync
source unavailable.  After both RPC endpoints are ready, ``--barrier-command``
makes that source available and this runner triggers Geth's target sync.  The
runner rejects any pre-barrier progress, records all lifecycle timestamps and
commands, and verifies the final block hash and execution roots before marking
the sample performance-eligible.
"""

from __future__ import annotations

import argparse
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
import json
import platform
import shlex
import subprocess
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


class RpcResponseError(SyncBenchmarkError):
    """Raised when a JSON-RPC endpoint returns a structured error."""

    def __init__(self, client: str, method: str, error: Any) -> None:
        self.client = client
        self.method = method
        self.error = error
        self.code = error.get("code") if isinstance(error, dict) else None
        super().__init__(f"{client} {method}: {error}")


class RpcClient:
    def __init__(self, name: str, url: str, timeout: float) -> None:
        self.name = name
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.request_id = 0

    def call(
        self, method: str, params: list[Any] | None = None, timeout: float | None = None
    ) -> Any:
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
            with urllib.request.urlopen(request, timeout=timeout or self.timeout) as response:
                body = json.load(response)
        except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            raise RpcFailure(f"{self.name} {method}: {error}") from error
        if not isinstance(body, dict):
            raise SyncBenchmarkError(f"{self.name} {method}: non-object JSON-RPC response")
        if "error" in body:
            raise RpcResponseError(self.name, method, body["error"])
        if "result" not in body:
            raise SyncBenchmarkError(f"{self.name} {method}: missing result")
        return body["result"]

    def call_batch(self, method: str, params: list[list[Any]]) -> list[Any]:
        if not params:
            return []
        payload: list[dict[str, Any]] = []
        request_ids: list[int] = []
        for call_params in params:
            self.request_id += 1
            request_ids.append(self.request_id)
            payload.append(
                {
                    "jsonrpc": "2.0",
                    "id": self.request_id,
                    "method": method,
                    "params": call_params,
                }
            )
        request = urllib.request.Request(
            self.url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"content-type": "application/json", "user-agent": "neox-sync-benchmark/1"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.load(response)
        except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            raise RpcFailure(f"{self.name} {method} batch: {error}") from error
        if not isinstance(body, list):
            raise SyncBenchmarkError(f"{self.name} {method} batch: non-array response")
        by_id: dict[int, Any] = {}
        for item in body:
            if not isinstance(item, dict) or not isinstance(item.get("id"), int):
                raise SyncBenchmarkError(f"{self.name} {method} batch: invalid response item")
            if "error" in item:
                raise SyncBenchmarkError(f"{self.name} {method} batch: {item['error']}")
            if "result" not in item:
                raise SyncBenchmarkError(f"{self.name} {method} batch: missing result")
            by_id[item["id"]] = item["result"]
        try:
            return [by_id[request_id] for request_id in request_ids]
        except KeyError as error:
            raise SyncBenchmarkError(
                f"{self.name} {method} batch: missing response id {error.args[0]}"
            ) from error

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
    process_started_at_utc: str | None = None
    rpc_ready_at_utc: str | None = None
    sync_triggered_at_utc: str | None = None
    completed_at_utc: str | None = None
    started_at: float | None = None
    reached_at: float | None = None
    samples: int = 0
    transient_errors: int = 0

    def result(self, start_height: int, target_height: int) -> dict[str, Any]:
        if self.started_at is None or self.reached_at is None:
            raise SyncBenchmarkError(f"{self.client.name}: target was not reached")
        elapsed = self.reached_at - self.started_at
        # A client may expose a head above the threshold when its pipeline
        # finishes a larger batch. Report the actual imported range rather
        # than attributing that work to the threshold height.
        imported = (self.end_head or target_height) - (self.start_head or start_height)
        return {
            "url": self.client.url,
            "client_version": self.version,
            "chain_id": self.chain_id,
            "start_height": self.start_head,
            "target_height": target_height,
            "end_height": self.end_head,
            "imported_blocks": imported,
            "process_started_at_utc": self.process_started_at_utc,
            "rpc_ready_at_utc": self.rpc_ready_at_utc,
            "sync_triggered_at_utc": self.sync_triggered_at_utc,
            "completed_at_utc": self.completed_at_utc,
            "elapsed_s": round(elapsed, 6),
            "blocks_per_second": round(imported / max(elapsed, 1e-9), 3),
            "samples": self.samples,
            "transient_errors": self.transient_errors,
        }


def read_head(client: RpcClient) -> int:
    return client.quantity("eth_blockNumber")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def validate_utc_timestamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"invalid ISO-8601 timestamp: {value}") from error
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError("process timestamps must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def final_block(client: RpcClient, height: int) -> dict[str, Any]:
    block = client.call("eth_getBlockByNumber", [hex(height), False])
    if not isinstance(block, dict):
        raise SyncBenchmarkError(f"{client.name}: block {height} is unavailable")
    return block


def verify_final_blocks(
    runs: list[ClientRun], target_height: int, reference_client: RpcClient | None = None
) -> dict[str, Any]:
    blocks = {run.client.name: final_block(run.client, target_height) for run in runs}
    if reference_client is not None:
        blocks[reference_client.name] = final_block(reference_client, target_height)
    fields = ("number", "hash", "parentHash", "stateRoot", "transactionsRoot", "receiptsRoot")
    reference_block = blocks[runs[0].client.name]
    mismatches: list[dict[str, Any]] = []
    for name, block in blocks.items():
        for field in fields:
            if block.get(field) != reference_block.get(field):
                mismatches.append(
                    {
                        "client": name,
                        "field": field,
                        "reference": reference_block.get(field),
                        "actual": block.get(field),
                    }
                )
    if mismatches:
        raise SyncBenchmarkError(f"final block mismatch: {mismatches}")
    return {
        "height": target_height,
        "number": reference_block.get("number"),
        "hash": reference_block.get("hash"),
        "parent_hash": reference_block.get("parentHash"),
        "state_root": reference_block.get("stateRoot"),
        "transactions_root": reference_block.get("transactionsRoot"),
        "receipts_root": reference_block.get("receiptsRoot"),
        "verified_fields": list(fields),
        "verified_endpoints": list(blocks),
    }


def transaction_stats(
    client: RpcClient, start_height: int, target_height: int, batch_size: int
) -> dict[str, int]:
    total = 0
    nonempty_blocks = 0
    for batch_start in range(start_height + 1, target_height + 1, batch_size):
        batch_end = min(batch_start + batch_size, target_height + 1)
        values = client.call_batch(
            "eth_getBlockTransactionCountByNumber",
            [[hex(height)] for height in range(batch_start, batch_end)],
        )
        for value in values:
            if not isinstance(value, str) or not value.startswith("0x"):
                raise SyncBenchmarkError(
                    f"{client.name}: invalid transaction count quantity {value!r}"
                )
            try:
                count = int(value, 16)
            except ValueError as error:
                raise SyncBenchmarkError(
                    f"{client.name}: invalid transaction count quantity {value!r}"
                ) from error
            total += count
            nonempty_blocks += int(count > 0)
    return {"transactions": total, "nonempty_blocks": nonempty_blocks}


def execute_barrier_command(command: str, timeout: float) -> dict[str, Any]:
    argv = shlex.split(command)
    started_at_utc = utc_now()
    started_at = time.perf_counter()
    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SyncBenchmarkError(f"barrier command failed: {error}") from error
    elapsed = time.perf_counter() - started_at
    result = {
        "started_at_utc": started_at_utc,
        "completed_at_utc": utc_now(),
        "elapsed_s": round(elapsed, 6),
        "exit_code": completed.returncode,
        "stdout": completed.stdout[-4096:],
        "stderr": completed.stderr[-4096:],
    }
    if completed.returncode != 0:
        raise SyncBenchmarkError(f"barrier command exited {completed.returncode}: {result}")
    return result


def trigger_outcome(future: Future[Any]) -> dict[str, Any]:
    """Classify the long-running Geth trigger independently from sync timing."""
    try:
        result = future.result()
    except RpcResponseError as error:
        if error.code != -32002:
            raise
        return {
            "status": "rpc_timeout_pending_target",
            "completed_at_utc": utc_now(),
            "result": None,
            "error": error.error,
        }
    return {
        "status": "completed",
        "completed_at_utc": utc_now(),
        "result": result,
        "error": None,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reth", required=True, help="neox-rs JSON-RPC URL")
    parser.add_argument("--geth", required=True, help="Neo X Geth JSON-RPC URL")
    parser.add_argument("--start-height", type=int, default=0)
    parser.add_argument("--target-height", type=int, required=True)
    parser.add_argument("--run-id", required=True, help="unique fresh-datadir run identifier")
    parser.add_argument("--reth-datadir", required=True)
    parser.add_argument("--geth-datadir", required=True)
    parser.add_argument("--reth-command", required=True, help="complete neox-rs launch command")
    parser.add_argument("--geth-command", required=True, help="complete Neo X Geth launch command")
    parser.add_argument(
        "--barrier-command",
        required=True,
        help="command executed once to make the shared sync source available",
    )
    parser.add_argument(
        "--reth-process-started-at", required=True, type=validate_utc_timestamp
    )
    parser.add_argument(
        "--geth-process-started-at", required=True, type=validate_utc_timestamp
    )
    parser.add_argument("--reference-rpc", help="canonical Neo X RPC used for the final-block gate")
    parser.add_argument(
        "--geth-sync-target",
        required=True,
        help=(
            "trigger Neo X Geth's debug_sync(hash) after both fresh endpoints are observed; "
            "use this instead of the startup-only --synctarget flag"
        ),
    )
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--trigger-timeout", type=float, default=120.0)
    parser.add_argument("--max-trigger-skew", type=float, default=1.0)
    parser.add_argument("--transaction-batch-size", type=int, default=500)
    parser.add_argument("--poll-interval", type=float, default=0.1)
    parser.add_argument("--deadline", type=float, default=300.0)
    parser.add_argument("--output", help="write JSON result to this path")
    args = parser.parse_args(argv)
    if args.start_height < 0:
        parser.error("--start-height cannot be negative")
    if args.target_height <= args.start_height:
        parser.error("--target-height must be greater than --start-height")
    if (
        args.timeout <= 0
        or args.trigger_timeout <= 0
        or args.max_trigger_skew <= 0
        or args.poll_interval <= 0
        or args.deadline <= 0
    ):
        parser.error("timeouts, trigger skew, poll interval, and deadline must be positive")
    if args.transaction_batch_size <= 0:
        parser.error("--transaction-batch-size must be positive")
    if args.reth_datadir == args.geth_datadir:
        parser.error("Reth and Geth must use different datadirs")
    if not shlex.split(args.reth_command) or not shlex.split(args.geth_command):
        parser.error("Reth and Geth launch commands cannot be empty")
    if not shlex.split(args.barrier_command):
        parser.error("--barrier-command cannot be empty")
    if args.geth_sync_target is not None:
        try:
            target = bytes.fromhex(args.geth_sync_target.removeprefix("0x"))
        except ValueError:
            parser.error("--geth-sync-target must be a 32-byte hex hash")
        if len(target) != 32:
            parser.error("--geth-sync-target must be a 32-byte hex hash")
    return args


def run(args: argparse.Namespace) -> dict[str, Any]:
    clients = [
        ClientRun(
            RpcClient("reth", args.reth, args.timeout),
            process_started_at_utc=args.reth_process_started_at,
        ),
        ClientRun(
            RpcClient("geth", args.geth, args.timeout),
            process_started_at_utc=args.geth_process_started_at,
        ),
    ]
    runner_started_at_utc = utc_now()
    expected_chain_id: int | None = None
    deadline = time.monotonic() + args.deadline
    barrier_at: float | None = None
    barrier_at_utc: str | None = None
    barrier_result: dict[str, Any] | None = None
    trigger_skew_s: float | None = None
    geth_trigger_outcome: dict[str, Any] | None = None
    sync_future: Future[Any] | None = None
    sync_executor: ThreadPoolExecutor | None = None
    geth = next(current for current in clients if current.client.name == "geth")
    reth = next(current for current in clients if current.client.name == "reth")
    try:
        while time.monotonic() < deadline and barrier_at is None:
            for current in clients:
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
                    if head != args.start_height:
                        raise SyncBenchmarkError(
                            f"{current.client.name}: pre-barrier head {head} does not equal "
                            f"start height {args.start_height}; sync began before the shared trigger"
                        )
                    if current.rpc_ready_at_utc is None:
                        current.start_head = head
                        current.rpc_ready_at_utc = utc_now()
                except RpcFailure:
                    if current.rpc_ready_at_utc is None:
                        current.transient_errors += 1
                        continue
                    raise

            if all(current.rpc_ready_at_utc is not None for current in clients):
                confirmation = {current.client.name: read_head(current.client) for current in clients}
                if any(head != args.start_height for head in confirmation.values()):
                    raise SyncBenchmarkError(
                        f"pre-barrier head changed during confirmation: {confirmation}"
                    )
                barrier_at = time.perf_counter()
                barrier_at_utc = utc_now()
                for current in clients:
                    current.started_at = barrier_at
                reth.sync_triggered_at_utc = barrier_at_utc
                barrier_result = execute_barrier_command(
                    args.barrier_command, args.trigger_timeout
                )
                geth_triggered_at = time.perf_counter()
                geth.sync_triggered_at_utc = utc_now()
                trigger_skew_s = geth_triggered_at - barrier_at
                if trigger_skew_s > args.max_trigger_skew:
                    raise SyncBenchmarkError(
                        f"trigger skew {trigger_skew_s:.6f}s exceeds "
                        f"{args.max_trigger_skew:.6f}s"
                    )
                sync_executor = ThreadPoolExecutor(max_workers=1)
                trigger_client = RpcClient("geth-trigger", args.geth, args.trigger_timeout)
                sync_future = sync_executor.submit(
                    trigger_client.call,
                    "debug_sync",
                    [args.geth_sync_target],
                    args.trigger_timeout,
                )
                break
            if barrier_at is None:
                time.sleep(args.poll_interval)

        if barrier_at is None:
            pending = [current.client.name for current in clients if current.rpc_ready_at_utc is None]
            raise SyncBenchmarkError(f"deadline expired before shared barrier: {pending}")

        while time.monotonic() < deadline and any(run.reached_at is None for run in clients):
            for current in clients:
                if current.reached_at is not None:
                    continue
                head = read_head(current.client)
                current.samples += 1
                if head >= args.target_height:
                    current.end_head = head
                    current.reached_at = time.perf_counter()
                    current.completed_at_utc = utc_now()
            if sync_future is not None and sync_future.done() and geth_trigger_outcome is None:
                geth_trigger_outcome = trigger_outcome(
                    sync_future
                )
            if any(current.reached_at is None for current in clients):
                time.sleep(args.poll_interval)

        if any(current.reached_at is None for current in clients):
            pending = [current.client.name for current in clients if current.reached_at is None]
            raise SyncBenchmarkError(f"deadline expired before target {args.target_height}: {pending}")
        if sync_future is not None and geth_trigger_outcome is None:
            geth_trigger_outcome = trigger_outcome(
                sync_future
            )
    finally:
        if sync_executor is not None:
            sync_executor.shutdown(wait=True, cancel_futures=True)

    reference_client = (
        RpcClient("reference", args.reference_rpc, args.timeout) if args.reference_rpc else None
    )
    final = verify_final_blocks(clients, args.target_height, reference_client)
    if (
        geth_trigger_outcome is not None
        and geth_trigger_outcome["status"] == "rpc_timeout_pending_target"
    ):
        geth_trigger_outcome["status"] = "target_reached_after_rpc_timeout"
    per_client_workload = {
        current.client.name: transaction_stats(
            current.client,
            args.start_height,
            args.target_height,
            args.transaction_batch_size,
        )
        for current in clients
    }
    if len(
        {
            (stats["transactions"], stats["nonempty_blocks"])
            for stats in per_client_workload.values()
        }
    ) != 1:
        raise SyncBenchmarkError(f"transaction workload mismatch: {per_client_workload}")
    workload = next(iter(per_client_workload.values()))
    return {
        "schema": "neox-sync-benchmark/v2",
        "metadata": {
            "run_id": args.run_id,
            "runner_started_at_utc": runner_started_at_utc,
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "eligibility": {
            "performance_eligible": True,
            "shared_trigger_barrier": True,
            "trigger_skew_s": round(trigger_skew_s or 0.0, 6),
            "max_trigger_skew_s": args.max_trigger_skew,
            "hash_root_gate": "passed",
            "transaction_count_gate": "passed",
        },
        "parameters": {
            "start_height": args.start_height,
            "target_height": args.target_height,
            "poll_interval": args.poll_interval,
            "geth_sync_target": args.geth_sync_target,
            "reference_rpc": args.reference_rpc,
            "reth_datadir": args.reth_datadir,
            "geth_datadir": args.geth_datadir,
        },
        "commands": {
            "reth": args.reth_command,
            "geth": args.geth_command,
            "barrier": args.barrier_command,
            "geth_trigger_rpc": {
                "method": "debug_sync",
                "params": [args.geth_sync_target],
            },
        },
        "timing": {
            "barrier_at_utc": barrier_at_utc,
            "barrier_command": barrier_result,
            "geth_trigger_rpc": geth_trigger_outcome,
            "process_started_at_utc": {
                current.client.name: current.process_started_at_utc for current in clients
            },
            "rpc_ready_at_utc": {
                current.client.name: current.rpc_ready_at_utc for current in clients
            },
            "sync_triggered_at_utc": {
                current.client.name: current.sync_triggered_at_utc for current in clients
            },
            "completed_at_utc": {
                current.client.name: current.completed_at_utc for current in clients
            },
        },
        "workload": {
            "start_height_exclusive": args.start_height,
            "end_height_inclusive": args.target_height,
            "blocks": args.target_height - args.start_height,
            **workload,
            "per_client": per_client_workload,
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
