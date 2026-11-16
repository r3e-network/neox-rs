# Neo X Geth delta through `b51d712adf`

## Overview

`bane-main` on 2026-10-29 is still `b51d712adf36544fce939767c9a08a4060117a59`
(`privnet: add Ethereum system contract allocation`, merged 2026-10-19). GitHub
`repos/bane-labs/go-ethereum/commits/bane-main` matches the local pin. There is
no newer commit to fetch.

`docs/neox/source-baseline.toml` already records that commit. This note is the
behavior check for every Neo X change after upstream geth `v1.17.5` / the
previous pin `f0e236838b`, and the one code change that check required.

MainNet and T4 genesis bytes are unchanged. The compatibility pin is
`b51d712adf`.

## Commit disposition

| Commit | What Geth changed | Rust |
|---|---|---|
| `84aae6942d` | Post-merge compile fixes. `PreExecution` takes the parent header. Beacon light-sync body fetch returns `(meta, bodies)`. | Amsterdam BAL plumbing. Neither public network schedules Amsterdam. The light-sync return order is inside Geth's downloader. |
| `76d0f119eb` | `FilterAdd(tx, local)` became `Filter(tx)`. With `--txpool.amevcache`, the cache pool is first and accepts every non-Envelope, non-`KeyManagementProxy` transaction, including remote gossip. Those transactions are not announced. | Deliberate. `--txpool.amevcache` still caches only `eth_sendRawTransaction`. Remote transactions stay in the public pool and are relayed. Swallowing them would make a public node drop ordinary transfers. The wallet flow in Geth's `antimev/README.md` submits the secret transaction by RPC. |
| `72579cf19c`, `9c4410e` | Block-access-list fields on dBFT pre-blocks and beacon body fetch. | Dormant until `amsterdamTime` is set. |
| `07ad807` | Beacon block fetcher checks `withdrawalsHash` instead of forcing an empty withdrawal list. | Reth body validation already checks the withdrawals root on Shanghai headers. |
| `8fde8c492f` | Remove `blobSchedule.osaka`. Osaka uses the Prague blob parameters. | Applied. Vendored genesis files have no `blobSchedule.osaka`. |
| `1518b4b` | `PreExecution` / `ProcessOnPersist` return errors instead of panicking. Engine V4/V5 `custodyColumns` wiring. | A failed OnPersist already fail-stops the block. Custody columns are Amsterdam/Bogota and dormant. |
| `4f9094d` | If a pathdb snapshot iterator fails, snap serving falls back to the trie iterator. | Geth pathdb serving. This client serves state through Reth's snap/state providers, which do not use that snapshot iterator. |
| `e4a6793` | Makefile archive/full sync targets. | Build-script only. |
| `cc7af690d0` | `waitForNewSealingProposal` ignores `lastProposal` while `syncing()` is true. `OnPayload` and `handleChainBlock` already returned early in that case. `bftSyncing` is `!beacon.InitialSynced() \|\| eth.Downloader.Syncing()`. | Applied. While any announced peer is more than one block ahead, the local round is parked: no proposal, no view-change timeout, no vote. `dbft/0` admission stays up so payloads are still validated and relayed. A one-block successor does not park the round. A node with no peers ahead still produces, which is what a single-validator network needs. |
| `496ae11` | `keeper` `go.mod` / `go.sum`. | Dependency-only. |
| `7c7b29a`, `9dec1dc364` | `finalGASUsed = gasPool.Used()`. | Already matched by cumulative successful transaction gas. |
| `66b1c842cc`, `b51d712adf` | Allocate the Ethereum system contracts in `privnet/{four,seven,single,zk}/genesis_privnet.json` only. | Not vendored. This client ships MainNet and T4 genesis, whose hashes are unchanged. A private network that wants those allocations loads Geth's updated genesis JSON. |

## API

`DescendantSyncTargets::pauses_dbft(head)` is true when a claimed or in-flight
sync target is at least two blocks above `head`.

`activate_dbft_round(..., participate)` refreshes Governance admission either
way. `participate == false` leaves the local round unset.

## Tests

- `dbft_participation_pauses_only_for_a_multi_block_gap`: head+1 does not pause; head+2 does.
- `dbft_activation_uses_the_notified_head_state_snapshot`: `participate == false` leaves the protocol active and the round unset.
