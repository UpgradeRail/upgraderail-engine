# Security

Version 0.1 receives security fixes while it is the current release. Report vulnerabilities privately to the repository maintainers.

WASM and TOML are untrusted inputs. WASM input is size-limited and parsed through `wasmparser`, `soroban-spec`, and bounded XDR decoding. Subprocess calls use argument arrays, not shell interpolation. RPC endpoints are sanitized before reporting and credentials must not be stored in configuration or manifests.

Manifest integrity is SHA-256 over the exact UTF-8 JSON file bytes. This detects modification but is not a signature. Simulation evidence describes only the scenarios and ledger state tested. The project has not received an external security audit.

