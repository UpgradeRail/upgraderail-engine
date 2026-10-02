# Report format

Text is intended for terminals, JSON for automation, and Markdown for review summaries. Machine-readable findings contain stable code, severity, title, message, and evidence. Overall state is `BLOCKED`, `READY_WITH_WARNINGS`, or `READY`.

Storage and authorization have explicit evidence states. `NOT PROVEN BY STATIC ANALYSIS` and `NOT TESTED` are not PASS results.

Runtime text and Markdown reports list each scenario, current and candidate outcome, authorization comparison, and runtime findings. A failed execution is rendered as `SIMULATION FAILED`; an absent scenario is `NOT CONFIGURED`.
