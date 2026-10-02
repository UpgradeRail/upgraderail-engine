# Architecture

`upgraderail-wasm` validates and normalizes Soroban artifacts. `upgraderail-analyzer` compares normalized specifications. `upgraderail-simulator` owns Stellar CLI, RPC, authorization, and resource evidence. `upgraderail-manifest` validates release inputs and commits exact report bytes. `upgraderail-report` renders data without analysis logic. `upgraderail-cli` orchestrates these libraries.

Static findings are deterministic for identical artifacts, configuration, and engine version. Network evidence must record ledger-dependent context separately.

