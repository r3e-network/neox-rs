#!/usr/bin/env python3
"""Compare every canonical block, transaction, and receipt across Neo X RPC endpoints."""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import sys
import time
from typing import Any


def load_single_height_differential():
    path = pathlib.Path(__file__).with_name("neox-rpc-differential.py")
    spec = importlib.util.spec_from_file_location("neox_rpc_differential", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DIFF = load_single_height_differential()


class FullDifferentialFailure(RuntimeError):
    """A transport or malformed-RPC response prevented the scan."""


def quantity(value: object, context: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise FullDifferentialFailure(f"{context}: expected hex quantity, got {value!r}")
    try:
        return int(value, 16)
    except ValueError as error:
        raise FullDifferentialFailure(f"{context}: invalid quantity {value!r}") from error


def compare(
    mismatches: list[dict[str, object]],
    category: str,
    key: str,
    expected: object,
    actual: object,
    client: str,
) -> None:
    if expected != actual:
        mismatches.append(
            {
                "category": category,
                "key": key,
                "reference": expected,
                "client": client,
                "actual": actual,
            }
        )


def compare_object(
    mismatches: list[dict[str, object]],
    category: str,
    identifier: str,
    expected: object,
    actual: object,
    fields: list[str],
    client: str,
) -> None:
    if not isinstance(expected, dict) or not isinstance(actual, dict):
        compare(mismatches, category, identifier, expected, actual, client)
        return
    for field in fields:
        compare(mismatches, category, f"{identifier}.{field}", expected.get(field), actual.get(field), client)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local", required=True, help="Rust/neox-rs JSON-RPC endpoint")
    parser.add_argument(
        "--reference",
        action="append",
        required=True,
        help="Geth or other reference endpoint; repeat for every validator",
    )
    parser.add_argument("--from-height", type=int, default=0)
    parser.add_argument(
        "--to-height",
        type=int,
        help="inclusive height; defaults to the minimum head across all endpoints",
    )
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--progress-every", type=int, default=100)
    args = parser.parse_args()
    if args.from_height < 0:
        parser.error("--from-height cannot be negative")
    if args.to_height is not None and args.to_height < args.from_height:
        parser.error("--to-height must be at least --from-height")
    if args.retries < 0:
        parser.error("--retries cannot be negative")
    if args.progress_every < 0:
        parser.error("--progress-every cannot be negative")

    urls = [args.local, *args.reference]
    labels = ["local", *[f"reference_{index}" for index in range(1, len(args.reference) + 1)]]
    clients = [DIFF.RpcClient(url, args.timeout) for url in urls]

    def call(client_index: int, method: str, params: list[object] | None = None) -> object:
        last: Exception | None = None
        for attempt in range(args.retries + 1):
            try:
                return clients[client_index].call(method, params)
            except Exception as error:  # noqa: BLE001 - normalize all RPC transport failures
                last = error
                if attempt < args.retries:
                    time.sleep(0.15 * (attempt + 1))
        raise FullDifferentialFailure(f"{labels[client_index]} {method}: {last}") from last

    try:
        heads = [quantity(call(index, "eth_blockNumber"), f"{labels[index]} eth_blockNumber") for index in range(len(clients))]
        target = min(heads) if args.to_height is None else args.to_height
        if any(head < target for head in heads):
            raise FullDifferentialFailure(
                f"requested height {target} is above an endpoint head: {dict(zip(labels, heads))}"
            )

        chain_ids = [call(index, "eth_chainId") for index in range(len(clients))]
        for index, chain_id in enumerate(chain_ids[1:], 1):
            if chain_id != chain_ids[0]:
                raise FullDifferentialFailure(
                    f"chain id mismatch: {labels[0]}={chain_ids[0]!r}, {labels[index]}={chain_id!r}"
                )

        mismatches: list[dict[str, object]] = []
        block_count = 0
        transaction_count = 0
        receipt_comparisons = 0
        status_counts: dict[str, int] = {}
        receipt_cache: dict[tuple[int, str], object] = {}

        for height in range(args.from_height, target + 1):
            tag = hex(height)
            blocks = [call(index, "eth_getBlockByNumber", [tag, False]) for index in range(len(clients))]
            reference_block = blocks[0]
            if not isinstance(reference_block, dict):
                raise FullDifferentialFailure(f"{labels[0]} block {height} is unavailable")
            reference_hashes = reference_block.get("transactions")
            if not isinstance(reference_hashes, list):
                raise FullDifferentialFailure(f"{labels[0]} block {height} has no transaction list")

            for index, block in enumerate(blocks):
                compare_object(
                    mismatches,
                    "block",
                    str(height),
                    reference_block,
                    block,
                    DIFF.BLOCK_FIELDS,
                    labels[index],
                )
                if isinstance(block, dict):
                    compare(mismatches, "transaction_hashes", str(height), reference_hashes, block.get("transactions"), labels[index])
                count = call(index, "eth_getBlockTransactionCountByNumber", [tag])
                compare(mismatches, "transaction_count", str(height), hex(len(reference_hashes)), count, labels[index])

            if reference_hashes:
                full_blocks = [call(index, "eth_getBlockByNumber", [tag, True]) for index in range(len(clients))]
                reference_full = full_blocks[0]
                if not isinstance(reference_full, dict) or not isinstance(reference_full.get("transactions"), list):
                    raise FullDifferentialFailure(f"{labels[0]} full block {height} is unavailable")
                reference_txs = reference_full["transactions"]
                if len(reference_txs) != len(reference_hashes):
                    raise FullDifferentialFailure(f"{labels[0]} block {height} transaction payload/count mismatch")
                transaction_count += len(reference_txs)

                # The local endpoint is the comparison baseline.  Query its receipts once for
                # status accounting, then compare the full payload only against references.
                for tx in reference_txs:
                    tx_hash = tx.get("hash") if isinstance(tx, dict) else None
                    if not isinstance(tx_hash, str):
                        raise FullDifferentialFailure(f"{height}: transaction hash is missing")
                    cache_key = (0, tx_hash)
                    if cache_key not in receipt_cache:
                        receipt_cache[cache_key] = call(0, "eth_getTransactionReceipt", [tx_hash])
                    local_receipt = receipt_cache[cache_key]
                    if isinstance(local_receipt, dict):
                        status = local_receipt.get("status")
                        if isinstance(status, str):
                            status_counts[status] = status_counts.get(status, 0) + 1

                for index, full_block in enumerate(full_blocks[1:], 1):
                    txs = full_block.get("transactions") if isinstance(full_block, dict) else None
                    if not isinstance(txs, list):
                        compare(mismatches, "transactions", str(height), reference_txs, txs, labels[index])
                        continue
                    compare(mismatches, "transaction_count", str(height), len(reference_txs), len(txs), labels[index])
                    for tx_index, (reference_tx, tx) in enumerate(zip(reference_txs, txs)):
                        tx_hash = reference_tx.get("hash") if isinstance(reference_tx, dict) else str(tx_index)
                        identifier = f"{height}:{tx_hash}"
                        compare_object(
                            mismatches,
                            "transaction",
                            identifier,
                            reference_tx,
                            tx,
                            DIFF.TRANSACTION_FIELDS,
                            labels[index],
                        )
                        if not isinstance(tx_hash, str):
                            raise FullDifferentialFailure(f"{identifier}: transaction hash is missing")
                        cache_key = (0, tx_hash)
                        if cache_key not in receipt_cache:
                            receipt_cache[cache_key] = call(0, "eth_getTransactionReceipt", [tx_hash])
                        reference_receipt = receipt_cache[cache_key]
                        receipt = call(index, "eth_getTransactionReceipt", [tx_hash])
                        compare_object(
                            mismatches,
                            "receipt",
                            identifier,
                            reference_receipt,
                            receipt,
                            DIFF.RECEIPT_FIELDS,
                            labels[index],
                        )
                        receipt_comparisons += 1

            block_count += 1
            if args.progress_every and block_count % args.progress_every == 0:
                print(
                    json.dumps(
                        {
                            "progress_height": height,
                            "target": target,
                            "blocks_checked": block_count,
                            "transactions_checked": transaction_count,
                            "mismatches": len(mismatches),
                        }
                    ),
                    flush=True,
                )

    except FullDifferentialFailure as error:
        print(json.dumps({"status": "error", "error": str(error)}, indent=2))
        return 2

    report: dict[str, Any] = {
        "status": "ok" if not mismatches else "mismatch",
        "endpoints": dict(zip(labels, urls)),
        "heads": dict(zip(labels, heads)),
        "chain_id": chain_ids[0],
        "from_height": args.from_height,
        "to_height": target,
        "blocks_checked": block_count,
        "transactions_checked": transaction_count,
        "receipt_comparisons": receipt_comparisons,
        "receipt_status_counts": status_counts,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches[:64],
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not mismatches else 1


if __name__ == "__main__":
    sys.exit(main())
