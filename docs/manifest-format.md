# Manifest format

Schema version 1 records engine version, generation time, Protocol 28 profile, release identity, both artifact identities, findings, simulations, and limitations. Engine-written JSON uses UTF-8, LF, and one trailing newline. The manifest hash is SHA-256 of those exact file bytes. Verification does not parse or reserialize the file.

