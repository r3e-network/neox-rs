# Neo X official ZK private network smoke — 2026-07-20

Runs one `neox-rs` validator beside the official Neo X Geth `privnet/zk` layout. This is a
live Anti-MEV consensus smoke test; it deliberately distinguishes the ZK network boot and
block-production boundary from the later DKG transaction window.

## Topology and artifacts

- Neo X Geth `a0c80295ab2c7a6d0bc218e4bc85270f5610948c`, from the public `privnet/zk` layout.
- One `neox-rs` validator on RPC `8661`, six Geth validators on `8662..8667`, and two Geth
  observers on `8660` and `8668`, all sharing chain ID `2312251829`.
- Official genesis: `/privnet/zk/genesis_privnet.json`, SHA-256
  `df3c5581d25992a0aa17402b10e145cc19625aef1ba2fe06cec09be6765a8a4c`.
- The six ceremony files were downloaded from the network-published ZK storage and checked
  against the pins in [`zk-anti-mev-2026-07-20.md`](zk-anti-mev-2026-07-20.md).
- The Geth validator-1 Anti-MEV keystore was migrated with `neox-dkg-migrate` into the Reth
  validator-bound encrypted format. The ECDSA account resolved to the same validator address.

## Mixed-client gate

Command:

```sh
scripts/neox-mixed-dkg-e2e.py \
  --reth http://127.0.0.1:8661 \
  --geth http://127.0.0.1:8660 --geth http://127.0.0.1:8662 \
  --geth http://127.0.0.1:8663 --geth http://127.0.0.1:8664 \
  --geth http://127.0.0.1:8665 --geth http://127.0.0.1:8666 \
  --geth http://127.0.0.1:8667 --geth http://127.0.0.1:8668 \
  --expected-geth 8 --minimum-blocks 10 --no-round-advance \
  --reth-metrics http://127.0.0.1:18661
```

The gate returned `status: ok`:

| check | result |
|---|---|
| clients | 1 Reth + 8 Geth = 9 |
| chain ID | `2312251829` on every client |
| common height | 70 → 80 |
| blocks checked | 11 |
| transient RPC errors | 0 |
| canonical reorgs | 0 |
| DKG contract round | 1 on every client |
| Reth protocol peers | 8 beacon + dBFT peers |

At the final sample, all nine RPC endpoints returned the same height-68 block hash
`0x9320f8c75f0902dba7683824ab812ff755c21689ff5d95a8145222a2f075042e` before the longer
gate continued to height 80. Reth imported and finalized Geth-produced Anti-MEV blocks while
the Geth validators continued producing the canonical chain.

## DKG window boundary

The official genesis stores `epochDuration = 720`, `sharePeriodDuration = 180`, and
`currentEpochStartHeight = 0`. Therefore the next DKG share window starts at height 360 and
the epoch target is height 720. At height 80 the Reth metrics were:

```text
reth_neox_dkg_current_round 2
reth_neox_dkg_queued_tasks 0
reth_neox_dkg_prover_attempts_total 0
reth_neox_dkg_submissions_total 0
reth_neox_dkg_confirmed_total 0
reth_neox_dkg_replacements_total 0
reth_neox_sync_dbft_view_changes_total 0
reth_neox_sync_canonical_reorgs_total 0
```

Zero DKG tasks here is expected: the network is still before `share_start`, not evidence that
the prover or submission path was exercised. A full official ZK release gate must run through
the share/recovery window and prove on-chain submission, receipt confirmation, Anti-MEV envelope
decryption, and the prover-delay/replacement/reorg fault scenarios.

## Conclusion

The official ZK genesis, ceremony artifacts, migrated keystore, Reth P2P/consensus integration,
and Geth/Reth Anti-MEV block agreement are now evidenced on a live nine-client private network.
The DKG/TPKE transaction lifecycle remains an explicit follow-up gate because the official timing
places it at heights 360–720.
