#!/usr/bin/env bash
set -euo pipefail

contracts_dir="${UPGRADERAIL_CONTRACTS_DIR:-../upgraderail-contracts}"
deployment="$contracts_dir/deployments/testnet.json"
wasm_dir="$contracts_dir/fixtures/wasm"

test -r "$deployment"
test -r "$wasm_dir/fleet_v1.wasm"
test -r "$wasm_dir/fleet_v2_compatible.wasm"
test -r "$wasm_dir/fleet_v2_breaking.wasm"
test -r "$wasm_dir/fleet_v2_migration.wasm"
test -r "$wasm_dir/upgrade_controller_v1.wasm"

python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("controller", d["controller"]["contract_id"], d["controller"]["wasm_hash"]); assert d["network"] == "testnet"' "$deployment"

cargo run --locked -q -p upgraderail-cli -- inspect "$wasm_dir/upgrade_controller_v1.wasm"
cargo run --locked -q -p upgraderail-cli -- compare --current "$wasm_dir/fleet_v1.wasm" --candidate "$wasm_dir/fleet_v2_compatible.wasm"
if cargo run --locked -q -p upgraderail-cli -- compare --current "$wasm_dir/fleet_v1.wasm" --candidate "$wasm_dir/fleet_v2_breaking.wasm"; then
  echo "breaking fixture unexpectedly passed" >&2
  exit 1
fi

migration_output="$(mktemp)"
trap 'rm -f "$migration_output"' EXIT
if cargo run --locked -q -p upgraderail-cli -- compare --current "$wasm_dir/fleet_v1.wasm" --candidate "$wasm_dir/fleet_v2_migration.wasm" >"$migration_output"; then
  echo "migration fixture unexpectedly passed" >&2
  cat "$migration_output" >&2
  exit 1
else
  migration_status=$?
  if [[ "$migration_status" -ne 1 ]]; then
    cat "$migration_output" >&2
    exit "$migration_status"
  fi
fi
grep -Fq 'Storage compatibility: NOT PROVEN BY STATIC ANALYSIS' "$migration_output"
