# Architecture

`upgraderail-wasm` separates input bounds, hashing, WASM validation, metadata, and Soroban specification normalization. `upgraderail-analyzer` compares normalized specifications by rule family. `upgraderail-simulator` owns Stellar CLI, RPC, Protocol 28 authorization XDR normalization, and resource evidence. `upgraderail-manifest` validates release inputs and commits exact report bytes. `upgraderail-report` renders data without analysis logic. `upgraderail-cli` orchestrates these libraries and exposes stable automation exit classes.

Static findings are deterministic for identical artifacts, configuration, and engine version. Network evidence must record ledger-dependent context separately.
