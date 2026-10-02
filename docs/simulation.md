# Simulation

The simulator validates Stellar CLI 28.x, calls Stellar RPC with timeouts, and supports authorization modes `enforce`, `record`, and `record_allow_nonroot`. Authorization discovery should use `record`.

Authorization and resource comparison functions operate on recorded runtime evidence. The v0.1 CLI currently reports `NOT CONFIGURED` when no executable scenario is present. It never converts absent evidence to PASS. Simulation cannot prove behavior outside the exact scenario and ledger state tested.

