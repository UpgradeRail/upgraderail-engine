# Contributing

Use Rust 1.98.1 and keep Protocol 28 dependencies pinned. Run:

```sh
cargo fmt --all -- --check
cargo check --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Tests that need `upgraderail-contracts` use the sibling checkout by default or `UPGRADERAIL_CONTRACTS_DIR`. Do not copy its WASM into this repository.

