#!/usr/bin/env bash
# G1b: reconcile with the 2026-09-08 baseline scope, which ran `cargo test -p <8 pkgs>`
# WITHOUT --tests --lib and therefore also collected the neox-rs [[bin]] unit tests (29).
# G2: strict clippy across the same eight packages.
set -uo pipefail

cd /d/Git/neox-rs || exit 1
source /c/Users/Administrator/AppData/Local/Temp/neox-msvc-env.sh

OUT=/d/Git/neox-rs/outputs/gate-20260909
mkdir -p "$OUT"

echo "########## G1b :: neox-rs --bins (baseline-scope delta) ##########"
cargo test -p neox-rs --bins > "$OUT/G1b-neox-rs-bins.log" 2>&1
echo "G1b rc=$?" | tee "$OUT/G1b-exit.txt"
grep -E 'Running|test result:' "$OUT/G1b-neox-rs-bins.log"

echo
echo "########## G2 :: strict clippy ##########"
PKG_LIST=(
  reth-neox-node
  reth-neox-antimev
  reth-neox-chainspec
  reth-neox-network
  reth-neox-consensus
  reth-neox-consensus-engine
  reth-neox-evm
  neox-rs
)
args=()
for pkg in "${PKG_LIST[@]}"; do args+=( -p "$pkg" ); done

cargo clippy "${args[@]}" --all-targets --no-deps -- -D warnings > "$OUT/G2-clippy.log" 2>&1
rc=$?
echo "G2 rc=$rc" | tee "$OUT/G2-exit.txt"
echo "warning lines: $(grep -ci 'warning' "$OUT/G2-clippy.log")"
grep -ciE '^warning' "$OUT/G2-clippy.log" | sed 's/^/cargo-warning-lines: /'
echo "--- tail ---"
tail -20 "$OUT/G2-clippy.log"
echo "########## DONE ##########"
