#!/usr/bin/env python3
"""Census historical Neo X Anti-MEV Envelope transactions to scope the PKCS#7 migration risk.

Connects to a Neo X JSON-RPC archive or full node and inspects blocks across the Anti-MEV
activation range, tracking Envelope transactions (targeting
0x1212000000000000000000000000000000000003) and whether the inner transaction their plaintext
`encrypted_hash` commits to also appears in the same block ("decrypted_replaced") or not
("fallback_or_retained").

The ciphertext is threshold-encrypted, so this tool cannot decrypt historical payloads and cannot
observe PKCS#7 padding bytes directly; a fallback can equally mean malformed padding, missing
shares, decoding failure, or pool refusal. Definitive padding verification requires the
historical committee's DKG key material or a mixed replay of the patched and legacy reference
clients.
"""

from __future__ import annotations

import argparse
import collections
import json
import logging
import sys
import time
import urllib.error
import urllib.request
from typing import Any

ANTIMEV_TARGET = "0x1212000000000000000000000000000000000003"
ENVELOPE_PREFIX = "0xffffffff"
MIN_CALDATA_BYTES = 348

# Known activation heights
MAINNET_ANTIMEV_BLOCK = 3749760
TESTNET_ANTIMEV_BLOCK = 2088000

logger = logging.getLogger("neox-scan-history-pkcs7")


class ScanFailure(RuntimeError):
    """RPC failure or parse exception during scanning."""


def rpc_call(url: str, method: str, params: list[Any], timeout: float = 30.0) -> Any:
    """Sends a single JSON-RPC 2.0 call."""
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "neox-scan-history-pkcs7/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise ScanFailure(f"RPC call {method} to {url} failed: {exc}") from exc

    if "error" in body:
        raise ScanFailure(f"RPC error from {method}: {body['error']}")
    return body.get("result")


def parse_envelope_data(data_hex: str) -> dict[str, Any] | None:
    """Parses Anti-MEV envelope calldata layout.

    Calldata layout (bytes):
      [0..4]    prefix (0xffffffff)
      [4..8]    dkgRound (uint32)
      [8..32]   padding (24 bytes)
      [32..80]  R (48 bytes compressed G1)
      [80..128] commitment (48 bytes compressed G1)
      [128..-36] encryptedMessage (variable length, 16-byte multiple)
      [-36..-4] encryptedHash (32 bytes B256)
      [-4..0]   encryptedGas (4 bytes uint32)
    """
    if not data_hex.startswith("0x"):
        return None
    raw = data_hex[2:]
    if len(raw) < MIN_CALDATA_BYTES * 2:
        return None
    if not raw.startswith("ffffffff"):
        return None

    try:
        raw_bytes = bytes.fromhex(raw)
    except ValueError:
        return None

    total_len = len(raw_bytes)
    if total_len < MIN_CALDATA_BYTES:
        return None

    prefix = raw_bytes[:4]
    dkg_round = int.from_bytes(raw_bytes[4:8], "big")
    encrypted_gas = int.from_bytes(raw_bytes[-4:], "big")
    encrypted_hash = "0x" + raw_bytes[-36:-4].hex()
    encrypted_message = raw_bytes[128:-36]

    if len(encrypted_message) == 0 or len(encrypted_message) % 16 != 0:
        return None

    return {
        "dkg_round": dkg_round,
        "encrypted_hash": encrypted_hash,
        "encrypted_gas": encrypted_gas,
        "encrypted_message_len": len(encrypted_message),
    }


def parse_block_antimev(
    block: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Inspects a block for Envelope transactions and matches with decrypted transactions."""
    transactions = block.get("transactions", [])
    if not transactions:
        return [], {}

    envelopes: list[dict[str, Any]] = []
    tx_by_hash: dict[str, dict[str, Any]] = {}

    for tx in transactions:
        if isinstance(tx, dict):
            tx_hash = tx.get("hash", "").lower()
            if tx_hash:
                tx_by_hash[tx_hash] = tx
            to_addr = (tx.get("to") or "").lower()
            if to_addr == ANTIMEV_TARGET.lower():
                parsed = parse_envelope_data(tx.get("input", ""))
                if parsed:
                    parsed["tx_hash"] = tx_hash
                    parsed["block_number"] = int(block.get("number", "0x0"), 16)
                    envelopes.append(parsed)

    findings: list[dict[str, Any]] = []
    stats: dict[str, int] = collections.defaultdict(int)

    for env in envelopes:
        stats["envelopes_found"] += 1
        expected_inner_hash = env["encrypted_hash"].lower()

        if expected_inner_hash in tx_by_hash:
            stats["decrypted_matches"] += 1
            decrypted_tx = tx_by_hash[expected_inner_hash]
            enc_len = env["encrypted_message_len"]

            finding = {
                "block": env["block_number"],
                "envelope_hash": env["tx_hash"],
                "inner_hash": expected_inner_hash,
                "dkg_round": env["dkg_round"],
                "encrypted_message_len": enc_len,
                "status": "decrypted_replaced",
            }
            findings.append(finding)
        else:
            stats["fallback_or_unmatched"] += 1
            finding = {
                "block": env["block_number"],
                "envelope_hash": env["tx_hash"],
                "inner_hash": expected_inner_hash,
                "dkg_round": env["dkg_round"],
                "encrypted_message_len": env["encrypted_message_len"],
                "status": "fallback_or_retained",
            }
            findings.append(finding)

    return findings, dict(stats)


def scan_blocks(
    url: str,
    start_block: int,
    end_block: int,
    batch_size: int = 20,
) -> dict[str, Any]:
    """Scans range of blocks for Anti-MEV Envelope records."""
    total_scanned = 0
    all_findings: list[dict[str, Any]] = []
    cumulative_stats: dict[str, int] = collections.defaultdict(int)
    start_time = time.time()

    current = start_block
    while current <= end_block:
        batch_end = min(current + batch_size - 1, end_block)
        for num in range(current, batch_end + 1):
            block = rpc_call(url, "eth_getBlockByNumber", [hex(num), True])
            if not block:
                continue
            total_scanned += 1
            findings, stats = parse_block_antimev(block)
            if findings:
                all_findings.extend(findings)
            for k, v in stats.items():
                cumulative_stats[k] += v

        current = batch_end + 1
        if total_scanned % 100 == 0 or current > end_block:
            logger.info("Scanned %d blocks up to %d...", total_scanned, current - 1)

    elapsed = time.time() - start_time
    return {
        "start_block": start_block,
        "end_block": end_block,
        "total_blocks_scanned": total_scanned,
        "elapsed_seconds": round(elapsed, 2),
        "cumulative_stats": dict(cumulative_stats),
        "findings_sample": all_findings[:100],
        "total_findings": len(all_findings),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc-url", required=True, help="Neo X JSON-RPC endpoint URL")
    parser.add_argument(
        "--start-block",
        type=int,
        default=None,
        help="Start block (defaults to network Anti-MEV fork height)",
    )
    parser.add_argument(
        "--end-block",
        type=int,
        default=None,
        help="End block (defaults to latest head)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=20,
        help="Number of blocks per batch",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="File path to write JSON audit report",
    )

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    chain_id_hex = rpc_call(args.rpc_url, "eth_chainId", [])
    chain_id = int(chain_id_hex, 16)
    logger.info("Connected to chain ID %d", chain_id)

    start_block = args.start_block
    if start_block is None:
        if chain_id == 47763:
            start_block = MAINNET_ANTIMEV_BLOCK
        elif chain_id == 12227332:
            start_block = TESTNET_ANTIMEV_BLOCK
        else:
            start_block = 0

    end_block = args.end_block
    if end_block is None:
        latest_hex = rpc_call(args.rpc_url, "eth_blockNumber", [])
        end_block = int(latest_hex, 16)

    logger.info("Scanning blocks %d to %d...", start_block, end_block)
    report = scan_blocks(args.rpc_url, start_block, end_block, args.batch_size)
    report["chain_id"] = chain_id

    report_json = json.dumps(report, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report_json)
        logger.info("Audit report written to %s", args.output)
    else:
        print(report_json)

    return 0


if __name__ == "__main__":
    sys.exit(main())
