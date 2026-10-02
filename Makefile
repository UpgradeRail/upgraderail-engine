.PHONY: check test integration

check:
	cargo fmt --all -- --check
	cargo check --workspace --locked
	cargo clippy --workspace --all-targets --locked -- -D warnings

test:
	cargo test --workspace --locked

integration:
	./scripts/integration-contracts.sh

