# Neo X all-Reth private validator network — 2026-07-19

Stands up a real private network of seven `neox-rs` validators (no Neo X Geth) to exercise the
validator block-production and dBFT consensus path in the pre-anti-MEV (ECDSA) regime, and records
the bugs it surfaced and fixed.

## Setup

- Seven `neox-rs` validators, each a separate process with its own datadir, ECDSA validator key,
  fixed devp2p key, and a full trusted-peer mesh (`--disable-discovery --trusted-peers … --ipcdisable`).
- A private genesis cloned from MainNet: private `chainId` (so no MainNet bootnodes), the DKG /
  AntiMev / EthSig forks pushed far out to keep the chain in the pure-ECDSA regime, the seven
  deterministic test validators written into both `config.dbft.standbyValidators` and the Governance
  proxy `currentConsensus` storage (the runtime reads its validator set from Governance state), and
  `extraData`/`mixHash` left unset so the chain spec derives the V0 dBFT genesis header.
- The validator runtime activated correctly on every node: `Activated local Neo X validator signer …
  validator_index=N`, confirming the set is read from Governance storage.

## Bugs found and fixed

The private network is the only setting that drives a Reth node as the block **producer** (on
MainNet, Geth produces and Reth validates), so it surfaced two production-side defects:

1. **Producer never attached the parent reseal witness.**
   `build_primary_proposal` hard-coded `parent_seal_hash_v0: None` and `parent_extra: None`. An
   ECDSA parent can be sealed with different honest quorum subsets — same dBFT seal hash, different
   block hash — so a backup holding a different witness of the parent needs the primary's exact
   parent witness to reseal it. Without it, every proposal built on an ECDSA parent was rejected
   with `MissingParentSealHash` and the network could not pass block 1. Fixed by attaching the seal
   hash and witness for ECDSA parents (`parent_reseal_witness`). This also makes Reth-produced
   proposals acceptable to Geth backups in a mixed network.
   Regression tests: `producer::tests::ecdsa_parent_proposal_carries_reseal_witness`,
   `producer::tests::threshold_parent_proposal_omits_reseal_witness`.

2. **Propagated-block import had no finality guard.**
   `import_propagated_block` ran `new_payload` + `fork_choice_updated` for any propagated block,
   including a competing same-height witness of an already finalized block. With several validators
   each gossiping their own block-1 witness, every node reorged on every arrival — an endless
   same-height reorg loop (observed >500k re-commits of block 1) that never reached the next height.
   dBFT finalizes each block on commit, so a propagated block must *advance* the head; fixed by
   importing only head-extending blocks (`propagated_block_extends_head`). MainNet tip-following is
   unaffected because live tip blocks are always `head + 1`.
   Regression test: `sync::tests::only_head_extending_propagated_blocks_are_imported`.

## Result

With both fixes, all seven validators converge and finalize dBFT blocks: every node reports the same
canonical head and hash, blocks advance with the in-turn/out-of-turn difficulty pattern, and each
block reaches the 5-of-7 commit quorum. Killing a validator leaves the remaining six (≥ quorum) and
the chain continues.

## Remaining issue (validator mode stays pre-release)

Sustained real-time production still stalls on a dBFT recovery-state conflict — a round gets stuck
in view 0 with `invalid dBFT recovery entry: PrepareRequest hash conflicts with accumulated
preparation state` while validators exchange `RecoveryRequest`s. This is a deeper recovery-merge
issue in multi-Reth-validator rounds that needs the mixed-client (Geth) behavior oracle to resolve
safely, and is the reason validator mode remains pre-release. The two fixes above are correct and
independently tested; they move an all-Reth network from "cannot leave block 1" to converged,
finalizing block production, and improve Reth↔Geth production compatibility.

## Reproduce

Use seven deterministic validator keys (secp256k1 secrets `0x01`..`0x07`), a MainNet-derived genesis
with the private `chainId`, far-future DKG/AntiMev/EthSig fork blocks, and those validators in both
`config.dbft.standbyValidators` and the Governance proxy `currentConsensus` storage. Launch each node
with `--chain <genesis> --validator.ecdsa-key <key> --p2p-secret-key-hex <secret> --disable-discovery
--ipcdisable --trusted-peers <mesh> --authrpc.port <distinct>` on distinct ports, then compare
`eth_blockNumber`/`eth_getBlockByNumber` across nodes to confirm converged, advancing heads.
