# Neo X protocol audit — 2026-10-29

## Verdict

Compared `crates/neox` with Neo X Geth `b51d712adf` (`bane-main`). That commit is two commits
after the pinned oracle `9dec1dc364`: `66b1c84` adds a private-network Ethereum system-contract
allocation, and `b51d712` merges it. Neither commit changes MainNet or T4 consensus rules, so the
compatibility pin stays at `9dec1dc364`.

This pass fixed the divergences that can make a Rust validator assemble a different block from a
Geth validator, disconnect a Geth peer, or (once Amsterdam is scheduled) verify a different seal.
It left in place the checks that are stricter than Geth on purpose, and the RPC methods Geth adds
on top of the standard Ethereum API. No remaining item forks a block an honest Geth quorum would
sign on today's MainNet or T4 schedules.

The live differential below was run on the release binary from before these fixes. Those 96,428
imported blocks already matched Geth's state root, receipts root, and gas used, so the execution
differences fixed here were not exercised as state forks in that window.

## Method

1. Area comparison of chainspec, dBFT, EVM and system calls, the transaction pool and JSON-RPC,
   Anti-MEV and DKG, and the beacon/dBFT wire protocols, against Geth `b51d712adf`.
2. Re-read of the Geth functions behind every fix in this change: `EncodeSigHeader`,
   `validateDecryptedTx`, `EffectiveGasTipCmp`, the static legacy pool (`NewStatic` has no promote
   channel), `VerifyBlock` / `VerifyEIP1559Header`, `systemCallGasBudget`, `Process` envelope
   counting, and `ProcessOnPersist`.
3. Regression tests in the Neo X crates. `cargo clippy` with `-D warnings` is clean for
   `neox-rs` and every `reth-neox-*` package (`--lib --tests --all-features`).
4. A MainNet catch-up of the pre-fix release binary, then an RPC differential against
   `mainnet-1.rpc.banelabs.org`.

## Live MainNet, pre-fix binary

The release binary caught up from block 8,039,772 to the live head, about 96,428 blocks, and
peered with MainNet Geth nodes on `beacon/2` and `dbft/0`.

| Check | Result |
|---|---|
| Imported blocks versus Geth header commitments (state root, receipts root, gas used) | 96,428 imported, no mismatch surfaced by execution or the Merkle stage |
| Head differential | 40 checks, 0 mismatches, 0 height skew |
| Execution differential on 40 blocks that contain transactions in the imported range | 7,396 field checks, 174 transactions, 0 mismatches |

## Fixes

| Divergence | Where Geth decides | What changed |
|---|---|---|
| Static reconstruction pool charged each sender's earlier transactions against the parent balance, and dropped a failed decrypted transaction before the Envelope was reconsidered | `legacypool.NewStatic` never promotes, so every transaction is checked alone against parent state. A decrypted transaction that passes `Add` and then fails `ApplyTransaction` stays queued, and the Envelope then loses `list.Add`'s 10% replacement bump | `StaticPoolAdmission` queues against parent nonce, parent balance, Policy, delegation, and authority limits. Replacement requires `STATIC_POOL_PRICE_BUMP` (10) and a strict increase of both fee fields. A failed decrypted execution stays queued, so the same-priced Envelope is `ReplaceUnderpriced` and the sender is skipped |
| Decrypted effective tip clamped at zero | `EffectiveGasTipCmp` compares the signed `feeCap - baseFee` once either cap is below the parent base fee | `signed_effective_tip` compares `I256` tips |
| `GetBlobs` TTL of 255 | `handleGetBlobs` rejects `Ttl < 1` and `handleGetBlobsPacket` rejects `Ttl > 3`, both by disconnecting. Geth originates TTL 3 | `MAX_BLOB_REQUEST_TTL = 3`. Inbound requests outside `1..=3` are not served or forwarded. This reverses the 2026-09-01 change that treated every non-zero TTL as accepted; that reading missed the second check |
| dBFT inbound errors disconnected peers Geth relays | `Pool.verify` checks the witness, then the height, then membership, and ignores `end == head` before membership. `OnPayload` logs a bad payload and returns nil | Witness first, exact-late ignore, then membership. A payload that does not decode, or whose validator index does not match, is logged and dropped. `ConsensusInactive` is ignored rather than disconnected |
| Policy blacklist skipped a zero-value `CALL` to an account created earlier in the same transaction | Geth `Exist` becomes true when the state object is created. revm's `LoadedAsNotExisting` flag is never cleared | The shortcut also requires that no journal entry has created, touched, or destroyed the account |
| Per-block Envelope limit used saturating conversion | `big.Int.Uint64` keeps the low 64 bits, so a stored `2^64` admits no Envelope | `envelope_limit_from_policy` returns the low limb |
| System calls received revm's 31,566,720 gas | `systemCallGasBudget` uses 30,000,000 before Amsterdam. The extra 1,566,720 is an EIP-8037 state-gas reservoir, and before Amsterdam revm will spend it as ordinary gas | `system_call_gas_limit` uses 30,000,000 until `SpecId::AMSTERDAM`, then revm's reservoir constant. A regression stores `gasleft()` and expects `29,999,998` |
| Amsterdam seal hash would cover two fields Geth omits | `EncodeSigHeader` stops at `requestsHash` | `unsigned_header` clears `block_access_list_hash` and `slot_number` before the ECDSA hash and the threshold message |
| A propagated block built on another seal of the current head was dropped | Geth's total-difficulty fork choice follows the child, which outweighs the head. ECDSA commits are not unique: two quorums can seal the same block with different signature subsets, and high-s is accepted | A block one or more above the local head is backfilled even when its parent is not the local head, under the existing descendant-sync budget. A block at or below the head height is still not imported over the head |

`NeoXEvm` now owns the revm instance directly. alloy-evm's `EthEvm` system-call helper always
installs revm's reservoir gas limit and does not offer another.

## Left unchanged

These are real differences. They do not change a block an honest Geth quorum produces on the
canonical schedules.

| Item | Why it stays |
|---|---|
| Policy `baseFee` is checked on every executed block (`validate_policy_base_fee`) | Geth's header check returns immediately for dBFT (`VerifyEIP1559Header`). The value check lives in `VerifyBlock`, which the consensus engine uses when vetting a proposal, not on `insertChain`. An honest primary copies the Policy slot into the header. Rejecting a mismatch fail-stops this node instead of following a quorum that signed a different fee. The live window above did not contain one |
| BLS points at infinity, and strict `ZK_VERSION` decoding | Already recorded under deliberate divergences in `docs/neox/README.md` |
| AES-CBC ciphertext whose length is not a multiple of 16 | Geth's `CryptBlocks` panics inside proposal processing. This client returns an error and falls back to the Envelope. Import does not decrypt, so the panic cannot fork state; matching it would take this process down |
| PreCommit share-count addition | Geth adds two `uint32` counts and can wrap into a huge allocation. This client widens first and rejects the message |
| Geth's light header verifier returns inside the batch loop | It is a pre-filter. Full checking still runs in the dBFT engine. This client only runs full validation |
| JSON-RPC surface | `eth_maxPriorityFeePerGas` uses the Reth oracle instead of Policy `minGasTipCap`. `eth_feeHistory`'s next base fee uses the EIP-1559 formula instead of `CalcBaseFeeDBFT`. `eth_sendRawTransaction` returns the outer Envelope hash; Geth returns the encrypted inner hash. `eth_estimateGas` does not raise fees to the Policy minimum before measuring. `eth_isAddressAllowed`, `eth_getBlobSidecars`, `eth_getBlobSidecarByTxHash`, and `eth_subscribe("envelopes")` are absent. None of these writes chain state |
| `GetTransactions` answers from the pool only | Geth also serves the miner's proposal cache. A backup recovering a proposal from a Rust validator can miss a transaction that never entered the Rust pool. It slows the view; it does not change an imported block |
| DKG submissions use a fixed 12,000,000 gas limit | Geth leaves gas unset and estimates. A share whose estimate exceeds 12,000,000 would run out of gas here and be retried. No measured ZK-v1 seven-message cost in this repo exceeds that cap |
| Custom genesis only | Neo X fork predicates are not gated on London (both canonical networks set `londonBlock` to 0). There is no `CheckConfigForkOrder`, no stored-config rewind check, and no Cancun BLS set when DKG is inactive. MainNet and T4 activate DKG before Cancun, so the precompile set matches there |
| Engine API nonce recovery tries only `0..validator_count` | Geth truncates the nonce with `uint8`. Honest primaries write the primary index. A nonce outside that range needs a colluding quorum and fails payload conversion here even though header validation accepts the truncated index |
| System calls do not warm address `0x0` | Geth warms the zero address and the target. revm's system-call path skips `load_accounts`. The difference is gas, and only for the zero address. The live window matched Geth's state roots with the previous, larger gas limit |

## Tests

Library tests after the fixes: `neox-rs` 31, `reth-neox-antimev` 47, `reth-neox-chainspec` 19,
`reth-neox-consensus` 19, `reth-neox-consensus-engine` 14, `reth-neox-evm` 33,
`reth-neox-network` 47, `reth-neox-node` 181. The Anti-MEV Geth vector suites
(`geth_ciphertext_admission`, `geth_cross_vectors`, `geth_negative_vectors`,
`geth_pkcs7_reachability`, `geth_reshare_vectors`) passed as well. New or rewritten coverage:

- Parent-balance checks are independent, gaps are queued, and replacement needs the 10% bump.
- A decrypted transaction that fails execution stays queued and blocks its Envelope.
- A negative effective tip is still ordered against the Envelope's negative tip.
- System-call `gasleft()` is `30,000,000 - 2` on Shanghai, Prague, and Osaka.
- Seal hash and threshold message ignore `block_access_list_hash` and `slot_number`.
- `GetBlobs` accepts TTL 1..=3 and rejects 0 and 4..=255.
- A propagated child of a sibling head seal is a backfill target; a block at the head height is not.
