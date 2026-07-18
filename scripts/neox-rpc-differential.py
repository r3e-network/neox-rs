#!/usr/bin/env python3
"""Compare a running neox-reth node with a Neo X Geth JSON-RPC endpoint."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request


POLICY_ADDRESS = "0x1212000000000000000000000000000000000002"
SYSTEM_ADDRESSES = [
    f"0x1212{'0' * 35}{suffix:x}" for suffix in range(9)
]
BLOCK_FIELDS = [
    "hash",
    "parentHash",
    "sha3Uncles",
    "miner",
    "stateRoot",
    "transactionsRoot",
    "receiptsRoot",
    "logsBloom",
    "difficulty",
    "number",
    "gasLimit",
    "gasUsed",
    "timestamp",
    "extraData",
    "mixHash",
    "nonce",
    "baseFeePerGas",
    "withdrawalsRoot",
    "blobGasUsed",
    "excessBlobGas",
    "parentBeaconBlockRoot",
    "requestsHash",
]


class RpcFailure(RuntimeError):
    pass


class RpcClient:
    def __init__(self, url: str, timeout: float) -> None:
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
                "user-agent": "neox-rpc-differential/1",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.load(response)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            raise RpcFailure(f"{self.url} {method}: {error}") from error
        if "error" in body:
            raise RpcFailure(f"{self.url} {method}: {body['error']}")
        return body.get("result")


def quantity(value: object) -> int:
    if not isinstance(value, str):
        raise RpcFailure(f"expected hex quantity, got {value!r}")
    return int(value, 16)


def compare(
    mismatches: list[dict[str, object]],
    category: str,
    key: str,
    local: object,
    reference: object,
) -> None:
    if local != reference:
        mismatches.append(
            {
                "category": category,
                "key": key,
                "local": local,
                "reference": reference,
            }
        )


def parse_height(value: str) -> int:
    return int(value, 0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local", default="http://127.0.0.1:8545")
    parser.add_argument("--reference", required=True)
    parser.add_argument("--height", type=parse_height)
    parser.add_argument("--max-height-skew", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()

    local = RpcClient(args.local, args.timeout)
    reference = RpcClient(args.reference, args.timeout)
    mismatches: list[dict[str, object]] = []

    try:
        local_head = quantity(local.call("eth_blockNumber"))
        reference_head = quantity(reference.call("eth_blockNumber"))
        height_skew = abs(local_head - reference_head)
        if height_skew > args.max_height_skew:
            mismatches.append(
                {
                    "category": "sync",
                    "key": "height_skew",
                    "local": local_head,
                    "reference": reference_head,
                }
            )
        height = args.height if args.height is not None else min(local_head, reference_head)
        block_tag = hex(height)

        compare(
            mismatches,
            "chain",
            "chainId",
            local.call("eth_chainId"),
            reference.call("eth_chainId"),
        )
        local_block = local.call("eth_getBlockByNumber", [block_tag, False])
        reference_block = reference.call("eth_getBlockByNumber", [block_tag, False])
        if not isinstance(local_block, dict) or not isinstance(reference_block, dict):
            raise RpcFailure(f"block {block_tag} is unavailable on one of the endpoints")
        for field in BLOCK_FIELDS:
            compare(
                mismatches,
                "block",
                field,
                local_block.get(field),
                reference_block.get(field),
            )

        for method in ["eth_gasPrice", "eth_envelopeFee", "eth_maxEnvelopeGas"]:
            compare(
                mismatches,
                "policy_rpc",
                method,
                local.call(method),
                reference.call(method),
            )

        for slot_number in [2, 3, 5, 6, 7]:
            slot = f"0x{slot_number:064x}"
            compare(
                mismatches,
                "policy_storage",
                str(slot_number),
                local.call("eth_getStorageAt", [POLICY_ADDRESS, slot, block_tag]),
                reference.call("eth_getStorageAt", [POLICY_ADDRESS, slot, block_tag]),
            )

        for address in SYSTEM_ADDRESSES:
            compare(
                mismatches,
                "system_code",
                address,
                local.call("eth_getCode", [address, block_tag]),
                reference.call("eth_getCode", [address, block_tag]),
            )
    except RpcFailure as error:
        print(json.dumps({"status": "error", "error": str(error)}, indent=2))
        return 2

    report = {
        "status": "ok" if not mismatches else "mismatch",
        "local_head": hex(local_head),
        "reference_head": hex(reference_head),
        "height": block_tag,
        "height_skew": height_skew,
        "checks": len(BLOCK_FIELDS) + 1 + 3 + 5 + len(SYSTEM_ADDRESSES),
        "mismatches": mismatches,
    }
    print(json.dumps(report, indent=2))
    return 0 if not mismatches else 1


if __name__ == "__main__":
    sys.exit(main())
