# Common development tasks

alias lint := clippy

fmt:
	cargo fmt --all

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

check:
	cargo check --all --all-features

test:
	cargo test --all --all-features

# Run all tests including ignored (requires Secret Service daemon for keychain tests)
# Uses --tests to skip doctests (which are intentionally incomplete examples)
test-all:
	cargo test --all-features --tests -- --include-ignored

docs:
	RUSTDOCFLAGS="--cfg docsrs" cargo doc --all-features --no-deps

deny:
	cargo deny check
