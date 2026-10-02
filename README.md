# UpgradeRail Engine

UpgradeRail Engine inspects and compares Soroban contract WASM before a governed upgrade is proposed. It is a terminal and CI tool. It does not deploy contracts, replace the UpgradeController, or provide a browser interface.

Static WASM analysis cannot prove all runtime authorization or storage behavior. A `READY` result means only that the configured checks found no blocker.

## Supported baseline

- Rust 1.99.0, edition 2021
- Soroban specification and Stellar XDR 28.0.0
- Protocol 28 analysis profile
- Stellar CLI 28.x for dynamic workflows

Protocol 29 Testnet may execute Protocol 28 artifacts, but that does not change the analysis profile.

## Install and use

```sh
cargo install --path crates/upgraderail-cli --locked
upgraderail inspect contract.wasm
upgraderail compare --current current.wasm --candidate candidate.wasm
upgraderail check --config upgraderail.toml
upgraderail manifest build --config upgraderail.toml --out release.json
upgraderail manifest hash release.json
upgraderail manifest verify release.json HASH
```

JSON is available from `inspect`, `compare`, and `check` with `--format json`. Exit code 1 means blocking findings, 2 means input or configuration failure, 3 means a missing or incompatible local dependency, 4 means an RPC or network failure, and 5 means an unexpected engine failure.

## Real contracts integration

The repository does not copy contract fixtures or Testnet deployment records. `scripts/integration-contracts.sh` reads the current checkout of `upgraderail-contracts`, including `deployments/testnet.json`, and analyzes its committed WASM. Set `UPGRADERAIL_CONTRACTS_DIR` when the repositories are not siblings.

See [architecture](docs/architecture.md), [analysis rules](docs/analysis-rules.md), [simulation limits](docs/simulation.md), and [known limitations](docs/limitations.md).

## Security and contributing

See [SECURITY.md](SECURITY.md) and [CONTRIBUTING.md](CONTRIBUTING.md). Licensed under Apache-2.0.
