# Static analysis rules

| Code | Severity | Meaning |
|---|---|---|
| FUNC001 | Blocking | Function removed |
| FUNC002 | Blocking | Function inputs changed |
| FUNC003 | Blocking | Function return changed |
| FUNC004 | Info | Function added |
| TYPE001/2/3 | Blocking/Blocking/Info | Public type removed, changed, or added |
| ERROR001/2/3 | Blocking/Blocking/Info | Error definition removed, changed, or added |
| EVENT001/2/3 | Blocking/Blocking/Info | Event removed, changed, or added |
| META001 | Warning | Metadata presence changed |
| SPEC010 | Info | Storage compatibility is not proved statically |
| SIM001 | Blocking | Policy requires simulation but none ran |
| AUTH001 | Warning | Recorded authorization differs |
| RESOURCE001 | Warning | Configured resource threshold exceeded |

Entries are compared from the Protocol 28 `SCSpecEntry` XDR representation, not Rust source.

