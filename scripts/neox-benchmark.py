#!/usr/bin/env python3
"""Reproducible NeoX Geth vs neox-rs JSON-RPC benchmark.

This is intentionally a small, dependency-free harness.  It uses one request
corpus against both clients, probes the corpus for semantic compatibility, and
only then records latency and throughput.  It is meant for engineering
comparisons, not synthetic claims about full-sync or transaction execution.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import itertools
import json
import os
import platform
import random
import statistics
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any


POLICY_ADDRESS = "0x1212000000000000000000000000000000000002"
IMPLEMENTATION_ADDRESS = "0x1212000000000000000000000000000000000000"
DEFAULT_SYSTEM_ADDRESSES = [
    f"0x1212{'0' * 35}{suffix:x}" for suffix in range(10)
]
DEFAULT_RETH_URL = "http://127.0.0.1:18546"
DEFAULT_GETH_URL = "http://127.0.0.1:18545"


class BenchmarkError(RuntimeError):
    """Raised when the benchmark cannot establish a fair comparison."""


@dataclasses.dataclass(frozen=True)
class BenchmarkCase:
    name: str
    method: str
    params: tuple[Any, ...]

    def payload(self) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": 1, "method": self.method, "params": list(self.params)}


class RpcClient:
    def __init__(self, name: str, url: str, timeout: float) -> None:
        self.name = name
        self.url = url.rstrip("/")
        self.timeout = timeout
        self._ids = itertools.count(1)
        self._id_lock = threading.Lock()

    def request(self, method: str, params: tuple[Any, ...] | list[Any] = ()) -> dict[str, Any]:
        with self._id_lock:
            request_id = next(self._ids)
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": list(params)}
        ).encode("utf-8")
        request = urllib.request.Request(
            self.url,
            data=payload,
            headers={"content-type": "application/json", "user-agent": "neox-benchmark/1"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.load(response)
        except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            raise BenchmarkError(f"{self.name} {method}: {error}") from error
        if not isinstance(body, dict):
            raise BenchmarkError(f"{self.name} {method}: JSON-RPC response is not an object")
        return body

    def result(self, method: str, params: tuple[Any, ...] | list[Any] = ()) -> Any:
        body = self.request(method, params)
        if "error" in body:
            raise BenchmarkError(f"{self.name} {method}: {body['error']}")
        return body.get("result")


def _hex_address(value: str) -> str:
    return value if value.startswith("0x") else f"0x{value}"


def _load_alloc_addresses(genesis_path: str | None) -> tuple[list[str], list[str]]:
    if not genesis_path:
        return [DEFAULT_SYSTEM_ADDRESSES[0]], DEFAULT_SYSTEM_ADDRESSES
    document = json.loads(Path(genesis_path).read_text(encoding="utf-8"))
    alloc = document.get("alloc", {})
    if not isinstance(alloc, dict):
        raise BenchmarkError("genesis alloc must be an object")
    accounts: list[str] = []
    code_accounts: list[str] = []
    for raw_address, account in sorted(alloc.items()):
        address = _hex_address(raw_address)
        if not isinstance(account, dict):
            continue
        accounts.append(address)
        if account.get("code"):
            code_accounts.append(address)
    if not accounts:
        accounts = [DEFAULT_SYSTEM_ADDRESSES[0]]
    if not code_accounts:
        code_accounts = list(DEFAULT_SYSTEM_ADDRESSES)
    return accounts[:4], code_accounts[:8]


def build_cases(genesis_path: str | None = None) -> list[BenchmarkCase]:
    """Build a fixed corpus from canonical NeoX genesis alloc entries."""

    accounts, code_accounts = _load_alloc_addresses(genesis_path)
    cases = [
        BenchmarkCase("rpc_chain_id", "eth_chainId", ()),
        BenchmarkCase("rpc_net_version", "net_version", ()),
        BenchmarkCase("block_header", "eth_getBlockByNumber", ("0x0", False)),
        BenchmarkCase("block_full", "eth_getBlockByNumber", ("0x0", True)),
    ]
    cases.extend(
        BenchmarkCase(f"balance_{index}", "eth_getBalance", (address, "latest"))
        for index, address in enumerate(accounts)
    )
    cases.extend(
        BenchmarkCase(f"code_{index}", "eth_getCode", (address, "latest"))
        for index, address in enumerate(code_accounts)
    )
    for slot in (2, 3, 5, 6, 7):
        cases.append(
            BenchmarkCase(
                f"policy_storage_{slot}",
                "eth_getStorageAt",
                (POLICY_ADDRESS, hex(slot), "latest"),
            )
        )
    # The implementation's empty fallback is successful on both clients and
    # exercises the EVM call path without relying on a head-dependent method.
    cases.append(
        BenchmarkCase(
            "evm_call_system_impl",
            "eth_call",
            ({"to": IMPLEMENTATION_ADDRESS, "data": "0x"}, "latest"),
        )
    )
    return cases


def _canonical_error(error: Any) -> dict[str, Any]:
    if not isinstance(error, dict):
        return {"error": str(error)}
    # Geth includes revert data for some calls while reth omits an empty data
    # field.  Error code and normalized message are the semantic comparison.
    message = str(error.get("message", ""))
    if message.startswith("execution reverted"):
        message = "execution reverted"
    return {"code": error.get("code"), "message": message}


def semantic_token(body: dict[str, Any]) -> str:
    if "error" in body:
        value: Any = {"error": _canonical_error(body["error"])}
    else:
        value = {"result": body.get("result")}
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _short_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]


def probe_cases(
    clients: dict[str, RpcClient], cases: list[BenchmarkCase]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    compatible: list[dict[str, Any]] = []
    mismatches: list[dict[str, Any]] = []
    for case in cases:
        replies = {name: client.request(case.method, case.params) for name, client in clients.items()}
        tokens = {name: semantic_token(reply) for name, reply in replies.items()}
        record = {
            "name": case.name,
            "method": case.method,
            "params": list(case.params),
            "response_hash": {name: _short_hash(token) for name, token in tokens.items()},
            "ok": len(set(tokens.values())) == 1,
        }
        if record["ok"]:
            compatible.append(record)
        else:
            record["responses"] = replies
            mismatches.append(record)
    return compatible, mismatches


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    values = sorted(values)
    index = max(0, min(len(values) - 1, int((len(values) - 1) * fraction + 0.5)))
    return values[index]


def _run_one(client: RpcClient, case: BenchmarkCase) -> tuple[float, bool, str | None]:
    started = time.perf_counter_ns()
    try:
        body = client.request(case.method, case.params)
        failed = "error" in body
        error = str(body["error"]) if failed else None
    except BenchmarkError as exc:
        failed, error = True, str(exc)
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    return elapsed_ms, failed, error


def measure(
    client: RpcClient,
    case: BenchmarkCase,
    requests: int,
    concurrency: int,
    warmup: int,
) -> dict[str, Any]:
    for _ in range(warmup):
        _run_one(client, case)
    started = time.perf_counter_ns()
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        samples = list(executor.map(lambda _: _run_one(client, case), range(requests)))
    elapsed_s = max(1e-9, (time.perf_counter_ns() - started) / 1_000_000_000)
    latencies = [sample[0] for sample in samples]
    errors = [sample[2] for sample in samples if sample[1] and sample[2]]
    return {
        "requests": requests,
        "errors": len(errors),
        "error_examples": errors[:3],
        "elapsed_s": round(elapsed_s, 6),
        "throughput_rps": round(requests / elapsed_s, 3),
        "latency_ms": {
            "min": round(min(latencies), 4) if latencies else 0.0,
            "mean": round(statistics.fmean(latencies), 4) if latencies else 0.0,
            "p50": round(_percentile(latencies, 0.50), 4),
            "p95": round(_percentile(latencies, 0.95), 4),
            "p99": round(_percentile(latencies, 0.99), 4),
            "max": round(max(latencies), 4) if latencies else 0.0,
        },
    }


def _median(values: list[float]) -> float:
    return round(statistics.median(values), 3) if values else 0.0


def _summary(rounds: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "rounds": len(rounds),
        "errors": sum(int(item["errors"]) for item in rounds),
        "throughput_rps_median": _median([float(item["throughput_rps"]) for item in rounds]),
    }
    for field in ("p50", "p95", "p99"):
        summary[f"latency_{field}_ms_median"] = _median(
            [float(item["latency_ms"][field]) for item in rounds]
        )
    return summary


def _metadata(clients: dict[str, RpcClient]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "hostname": platform.node(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "logical_cpus": os.cpu_count(),
    }
    for name, client in clients.items():
        result[name] = {
            "url": client.url,
            "client_version": client.result("web3_clientVersion"),
            "chain_id": client.result("eth_chainId"),
            "block_number": client.result("eth_blockNumber"),
        }
    return result


def _parse_concurrency(value: str) -> list[int]:
    values = [int(item) for item in value.split(",") if item.strip()]
    if not values or any(item <= 0 for item in values):
        raise argparse.ArgumentTypeError("concurrency values must be positive integers")
    return values


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reth", default=DEFAULT_RETH_URL, help="neox-rs HTTP RPC URL")
    parser.add_argument("--geth", default=DEFAULT_GETH_URL, help="NeoX Geth HTTP RPC URL")
    parser.add_argument("--genesis", help="canonical NeoX genesis JSON used to build alloc corpus")
    parser.add_argument("--requests", type=int, default=1000, help="timed requests per case/client/round")
    parser.add_argument("--warmup", type=int, default=100, help="warmup requests per case/client/round")
    parser.add_argument("--rounds", type=int, default=3, help="timed rounds per case/client")
    parser.add_argument("--concurrency", type=_parse_concurrency, default=[1, 4, 16])
    parser.add_argument("--timeout", type=float, default=10.0, help="per-RPC timeout in seconds")
    parser.add_argument("--seed", type=int, default=20260720, help="fixed run-order seed")
    parser.add_argument("--only", help="comma-separated case names to benchmark")
    parser.add_argument("--output", help="write JSON report to this path instead of stdout")
    parser.add_argument(
        "--allow-mismatch",
        action="store_true",
        help="benchmark compatible cases even when the probe finds mismatches",
    )
    args = parser.parse_args(argv)
    if args.requests <= 0 or args.warmup < 0 or args.rounds <= 0:
        parser.error("requests/rounds must be positive and warmup cannot be negative")
    return args


def run(args: argparse.Namespace) -> dict[str, Any]:
    clients = {
        "reth": RpcClient("reth", args.reth, args.timeout),
        "geth": RpcClient("geth", args.geth, args.timeout),
    }
    metadata = _metadata(clients)
    cases = build_cases(args.genesis)
    if args.only:
        selected = {name.strip() for name in args.only.split(",") if name.strip()}
        cases = [case for case in cases if case.name in selected]
        missing = selected - {case.name for case in cases}
        if missing:
            raise BenchmarkError(f"unknown benchmark case(s): {', '.join(sorted(missing))}")
    compatible, mismatches = probe_cases(clients, cases)
    if mismatches and not args.allow_mismatch:
        raise BenchmarkError(
            "semantic probe mismatch; refusing unfair comparison: "
            + ", ".join(item["name"] for item in mismatches)
        )
    compatible_names = {item["name"] for item in compatible}
    benchmark_cases = [case for case in cases if case.name in compatible_names]
    rng = random.Random(args.seed)
    results: dict[str, dict[str, dict[str, Any]]] = {name: {} for name in clients}
    for concurrency in args.concurrency:
        for case in benchmark_cases:
            # Pair each client's measurement in the same round and randomize
            # which endpoint goes first.  This limits thermal/cache drift from
            # systematically favoring one implementation.
            rounds_by_client: dict[str, list[dict[str, Any]]] = {name: [] for name in clients}
            for _ in range(args.rounds):
                order = list(clients)
                rng.shuffle(order)
                for name in order:
                    rounds_by_client[name].append(
                        measure(clients[name], case, args.requests, concurrency, args.warmup)
                    )
            for name, rounds in rounds_by_client.items():
                results[name].setdefault(case.name, {})[str(concurrency)] = {
                    "summary": _summary(rounds),
                    "rounds": rounds,
                }
    return {
        "schema": "neox-benchmark/v1",
        "metadata": metadata,
        "parameters": {
            "requests": args.requests,
            "warmup": args.warmup,
            "rounds": args.rounds,
            "concurrency": args.concurrency,
            "seed": args.seed,
        },
        "cases": [dataclasses.asdict(case) for case in cases],
        "probe": {"compatible": compatible, "mismatches": mismatches},
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = run(args)
    except (BenchmarkError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"neox-benchmark: {error}", file=sys.stderr)
        return 2
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
