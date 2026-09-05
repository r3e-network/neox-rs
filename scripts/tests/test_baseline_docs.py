"""Baseline-documentation consistency: README against docs/neox/source-baseline.toml.

The TOML is the single source of record for the compatibility oracle; the README baseline table
must quote the same values so the two documents cannot drift apart (review finding R11).
"""

from __future__ import annotations

import pathlib
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
BASELINE = ROOT / "docs" / "neox" / "source-baseline.toml"
README = ROOT / "README.md"


def load_baseline() -> dict:
    with BASELINE.open("rb") as handle:
        return tomllib.load(handle)


class BaselineDocsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.baseline = load_baseline()
        self.readme = README.read_text(encoding="utf-8")

    def test_readme_quotes_the_current_reth_baseline(self) -> None:
        reth = self.baseline["reth"]
        for value in (reth["commit"], reth["version"], reth["tip_under_review"]):
            self.assertIn(value, self.readme, f"README must quote the reth baseline {value}")

    def test_readme_quotes_the_geth_oracle_baseline(self) -> None:
        geth = self.baseline["neox_geth"]
        for value in (geth["commit"], geth["branch"], geth["version"]):
            self.assertIn(value, self.readme, f"README must quote the oracle baseline {value}")

    def test_readme_quotes_both_genesis_chain_ids(self) -> None:
        for key in ("mainnet", "testnet"):
            genesis = self.baseline["neox_geth"]["genesis"][key]
            self.assertIn(str(genesis["chain_id"]), self.readme)

    def test_genesis_fingerprints_are_declared_as_oracle_bytes(self) -> None:
        text = BASELINE.read_text(encoding="utf-8")
        self.assertIn(
            "ORACLE's original bytes",
            text,
            "the genesis entries must document that sha256 fingerprints the oracle bytes, "
            "not the repository file",
        )

    def test_genesis_paths_exist_in_the_repository(self) -> None:
        for key in ("mainnet", "testnet"):
            genesis = self.baseline["neox_geth"]["genesis"][key]
            self.assertTrue((ROOT / genesis["path"]).is_file(), genesis["path"])


if __name__ == "__main__":
    unittest.main()
