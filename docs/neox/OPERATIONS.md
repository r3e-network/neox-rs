# Neo X node operations

This runbook covers non-validator backup/restore and the additional fencing required for a
validator. Commands assume a locally built release bundle and Neo X MainNet (`chain_id=47763`).

## Snapshot backup

Use a filesystem with enough free space for both the compressed archives and a fully allocated
restored database. MDBX files can be sparse in the source datadir, so `du` alone may materially
underestimate restore space.

1. Record the canonical height and hash, stop the node cleanly, and confirm no process still has the
   datadir open. A snapshot produced from a live or abruptly stopped database is not a release
   backup.
2. Generate a modular archive from the closed datadir:

   ```sh
   neox-reth snapshot-manifest \
     --source-datadir /srv/neox/data \
     --output-dir /srv/neox/backups/2026-07-19 \
     --chain-id 47763
   ```

3. Inspect `manifest.json`. Require `chain_id` 47763, the expected block, and the expected storage
   version before moving the backup to immutable storage:

   ```sh
   jq '{block, chain_id, storage_version, reth_version, components: (.components | keys)}' \
     /srv/neox/backups/2026-07-19/manifest.json
   ```

Keep the manifest and every referenced archive together. Do not edit their paths or checksums.
The node's P2P identity, JWT secret, validator keys, passwords, DKG keystore, prover, and ZK
artifacts are operational secrets/configuration and must be backed up separately.

## Restore gate

Always restore into a new empty directory. The downloader verifies each manifest-declared archive
and extracted output before completing:

```sh
neox-reth download \
  --chain neox-mainnet \
  --datadir /srv/neox/restore-candidate \
  --manifest-path /srv/neox/backups/2026-07-19/manifest.json \
  --archive \
  --non-interactive
```

Start the restored node on isolated ports without validator credentials. Let it reach the reference
head, then require healthy Neo X peers and a clean differential result:

```sh
neox-reth node \
  --chain neox-mainnet \
  --datadir /srv/neox/restore-candidate \
  --port 31340 \
  --http --http.addr 127.0.0.1 --http.port 18650 \
  --ws --ws.addr 127.0.0.1 --ws.port 18651 \
  --metrics 127.0.0.1:18652

scripts/neox-rpc-differential.py \
  --local http://127.0.0.1:18650 \
  --reference https://mainnet-1.rpc.banelabs.org
```

The gate passes only when the node starts from the restored state, resumes canonical sync, has
BEACON and dBFT peers, and reports zero differential mismatches. Stop it cleanly before promoting
the restored datadir.

## Validator recovery fencing

- Never run two validator processes with the same ECDSA key or DKG identity. Fence validator duty
  before reading, copying, restoring, or migrating any validator state.
- Restore the chain snapshot first and catch up as a non-validator. Restore the encrypted DKG
  keystore separately; retrieve its password, ECDSA key, pinned prover, manifest, and approved ZK
  artifacts from their independent secret/configuration stores.
- Before re-enabling duty, confirm the restored message public key, validator address, DKG round,
  current/previous shares, and canonical Governance/KeyManagement state all match. Any mismatch is
  a hard stop, not a reason to reinitialize the keystore.
- Keep the old deployment fenced until the replacement has completed DKG reconciliation and an
  operator has transferred duty explicitly.

## Upgrade and rollback

1. Run the release bundle's checksum verification and `neox-reth --version` check.
2. Exercise the new binary against a restored snapshot on isolated ports. Run the differential gate
   and inspect Neo X metrics before touching the production datadir.
3. Back up the production node, stop it cleanly, then start the new binary against the existing
   datadir. Confirm database version, canonical height, peer counts, rejected-transition rate, reorg
   counter, Policy RPC, and system-contract code.
4. A binary-only rollback is safe only when the release notes state that no irreversible storage
   migration occurred. Otherwise stop the node and restore the pre-upgrade snapshot to a new
   datadir. Never point an older binary at a database already migrated by a newer release.

For a validator upgrade, apply the fencing rules above in addition to this sequence. Keep validator
duty disabled until the upgraded node is caught up and its DKG state has reconciled.

## Health criteria

- `reth_neox_sync_canonical_height` advances with the reference network.
- `reth_neox_sync_beacon_peers` and `reth_neox_sync_dbft_peers` remain non-zero.
- `reth_neox_sync_dbft_transitions_rejected_total` does not grow persistently. An isolated invalid
  peer message can be rejected without indicating a local fault.
- `reth_neox_sync_canonical_reorgs_total` changes only when the canonical chain actually reorganizes.
- `scripts/neox-rpc-differential.py` completes all checks without a mismatch after start, restore,
  upgrade, and rollback exercises.
