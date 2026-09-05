"""Unit tests for the Neo X historical Anti-MEV / PKCS#7 padding scanner."""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "neox-scan-history-pkcs7.py"
SPEC = importlib.util.spec_from_file_location("neox_scan_history_pkcs7", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
SCANNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SCANNER
SPEC.loader.exec_module(SCANNER)


class ScanHistoryPkcs7Tests(unittest.TestCase):
    def test_parses_valid_envelope_data(self) -> None:
        # 4 (prefix) + 4 (round) + 24 (padding) + 48 (R) + 48 (cmt) + 32 (msg) + 32 (hash) + 4 (gas) = 196 bytes
        # Must be >= 348 bytes. Let's make an envelope with 348 bytes.
        prefix = bytes.fromhex("ffffffff")
        dkg_round = (5).to_bytes(4, "big")
        padding = bytes([0] * 24)
        r_slot = bytes([1] * 48)
        cmt_slot = bytes([2] * 48)
        # 348 - 4 - 4 - 24 - 48 - 48 - 32 - 4 = 184 bytes for message. 184 is a multiple of 16 (184 = 16 * 11 + 8? No, 184 / 16 = 11.5)
        # Let's use 192 bytes for message (192 / 16 = 12).
        # Total = 192 + 160 = 352 bytes. 352 >= 348.
        msg = bytes([0xAA] * 192)
        inner_hash = bytes([0x42] * 32)
        gas = (21000).to_bytes(4, "big")

        raw = prefix + dkg_round + padding + r_slot + cmt_slot + msg + inner_hash + gas
        self.assertGreaterEqual(len(raw), 348)
        self.assertEqual(len(msg) % 16, 0)

        parsed = SCANNER.parse_envelope_data("0x" + raw.hex())
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed["dkg_round"], 5)
        self.assertEqual(parsed["encrypted_hash"], "0x" + inner_hash.hex())
        self.assertEqual(parsed["encrypted_gas"], 21000)
        self.assertEqual(parsed["encrypted_message_len"], 192)

    def test_rejects_non_envelope_calldata(self) -> None:
        # Too short
        self.assertIsNone(SCANNER.parse_envelope_data("0x1234"))
        # Missing ffffffff prefix
        self.assertIsNone(SCANNER.parse_envelope_data("0x00000000" + "00" * 350))
        # Not hex
        self.assertIsNone(SCANNER.parse_envelope_data("invalid"))

    def test_matches_decrypted_transaction_in_block(self) -> None:
        prefix = bytes.fromhex("ffffffff")
        dkg_round = (1).to_bytes(4, "big")
        padding = bytes([0] * 24)
        r_slot = bytes([1] * 48)
        cmt_slot = bytes([2] * 48)
        msg = bytes([0xBB] * 192)
        inner_hash = bytes.fromhex("11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff")
        gas = (50000).to_bytes(4, "big")
        envelope_calldata = "0x" + (prefix + dkg_round + padding + r_slot + cmt_slot + msg + inner_hash + gas).hex()

        block = {
            "number": "0x100",
            "transactions": [
                {
                    "hash": "0xenv001",
                    "to": SCANNER.ANTIMEV_TARGET,
                    "input": envelope_calldata,
                },
                {
                    "hash": "0x" + inner_hash.hex(),
                    "to": "0x1111111111111111111111111111111111111111",
                    "input": "0x",
                },
            ],
        }

        findings, stats = SCANNER.parse_block_antimev(block)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["status"], "decrypted_replaced")
        self.assertEqual(findings[0]["inner_hash"], "0x" + inner_hash.hex())
        self.assertEqual(stats["envelopes_found"], 1)
        self.assertEqual(stats["decrypted_matches"], 1)
        self.assertEqual(stats.get("fallback_or_unmatched", 0), 0)


if __name__ == "__main__":
    unittest.main()
