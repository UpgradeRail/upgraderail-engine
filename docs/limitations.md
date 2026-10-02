# Known limitations

- Static inspection cannot prove storage invariants, migration completeness, or runtime authorization.
- Source-level behavior and private storage key usage are not analyzed.
- The analysis profile is Protocol 28 only.
- Simulation results cover only configured calls at the recorded ledger state.
- Version 0.1 does not clone production state or formally verify contracts.
- The recorded Testnet deployment proves governed upgrades and preserved values for two shared-reference instances, but it does not currently provide a separately addressable pre-upgrade and candidate fleet pair for a live current/candidate simulation.
