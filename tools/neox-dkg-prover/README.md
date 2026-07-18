# Neo X DKG prover helper

`neox-dkg-prover` is the narrow compatibility boundary between the Rust node and Neo X's deployed
gnark-based DKG verifier. It uses the same `bane-labs/zk-dkg` v0.3.0, gnark v0.13.0, and
gnark-crypto v0.18.0 versions as Neo X Geth.

The helper accepts one JSON request on stdin and emits one JSON response on stdout. Secret shares
must not be supplied through command-line arguments or environment variables. ZK-v1 requests must
use absolute R1CS and proving-key paths and pin both files by SHA-256. ZK-v0 requests perform only
the contract-compatible ECIES encryption and reject proof-artifact fields.

The full-node runtime configuration, manifest schema, artifact pinning procedure, and crash/reorg
recovery rules are documented in [`docs/neox/README.md`](../../docs/neox/README.md). Start from
[`dkg-prover-manifest.example.json`](../../docs/neox/dkg-prover-manifest.example.json) and replace
every zero digest with the SHA-256 of the network-approved artifact.

Build and test it with:

```sh
go test ./...
go build ./...
```

The `github.com/bane-labs/zk-dkg` dependency is MIT licensed. Its license is preserved in the Go
module cache and published source distribution through the dependency metadata.
