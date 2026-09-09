#!/usr/bin/env bash
# G1 gate: cargo test --tests --lib across the eight Neo X crates.
# Independent verification of HEAD == 2da0e8fc9c9a42359a9d13053a9d5cbc7259d22c
set -uo pipefail

cd /d/Git/neox-rs || exit 1
source /c/Users/Administrator/AppData/Local/Temp/neox-msvc-env.sh

OUT=/d/Git/neox-rs/outputs/gate-20260909
mkdir -p "$OUT"

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

SUMMARY="$OUT/G1-summary.txt"
: > "$SUMMARY"

for pkg in "${PKG_LIST[@]}"; do
  log="$OUT/G1-${pkg}.log"
  echo "=== G1 :: -p ${pkg} :: cargo test --tests --lib ===" | tee -a "$SUMMARY"
  start=$SECONDS
  cargo test -p "$pkg" --tests --lib > "$log" 2>&1
  rc=$?
  dur=$(( SECONDS - start ))
  {
    echo "package : $pkg"
    echo "exit_rc : $rc"
    echo "duration: ${dur}s"
    echo "--- parsed result lines ---"
    grep -E '^test result:' "$log" || echo "(no 'test result:' line found)"
    echo "--- totals ---"
    grep -E '^test result:' "$log" \
      | awk '{for(i=1;i<=NF;i++){if($i=="passed;")p+=$0*0+$(i-1); if($i=="failed;")f+=$(i-1); }} END{printf "passed=%d failed=%d\n", p, f}'
    echo
  } | tee -a "$SUMMARY"
  echo "G1 $pkg rc=$rc dur=${dur}s" >> "$OUT/progress.log"
done

echo "=== G1 ALL DONE ===" | tee -a "$SUMMARY"
