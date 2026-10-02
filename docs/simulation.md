# Simulation

The simulator validates Stellar CLI 28.x, calls Stellar RPC with timeouts, and supports authorization modes `enforce`, `record`, and `record_allow_nonroot`. Authorization discovery should use `record`.

Authorization evidence is decoded from Protocol 28 `SorobanAuthorizationEntry` XDR. The engine compares credential form and identity, the recursive invocation tree, contract target, function, and arguments. It retains raw XDR when decoding fails and reports that normalization was unavailable rather than treating it as a match.

Text and Markdown reports show each configured scenario's current and candidate result, authorization comparison, and runtime findings. The CLI reports `NOT CONFIGURED` when no executable scenario is present. It never converts absent evidence to PASS. Simulation cannot prove behavior outside the exact scenario and ledger state tested.
