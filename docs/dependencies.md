# Dependencies

Protocol-critical dependencies are exactly `soroban-spec 28.0.0`, `stellar-xdr 28.0.0`, and the compatible `wasmparser 0.116.1`. General dependencies are recorded in `Cargo.toml` and locked by `Cargo.lock`.

Direct dependencies provide CLI parsing, serialization, hashing, errors, asynchronous process execution, HTTPS JSON-RPC, timestamps, and URL redaction. Versions were verified with Rust 1.99.0. `soroban-spec 28.0.0` declares Rust 1.91 as its minimum and already depends on `wasmparser 0.116.1`.
