# Common development tasks

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

check:
	cargo check --all --all-features

pedantic:
	cargo clippy --all-features -- -W clippy::pedantic

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

# CI-style platform smoke checks (cross-compile from Linux)
# Note: Windows/macOS recipes are compile-only checks, not runtime tests.
ci-linux:
	cargo check --all --all-features
	cargo clippy --all-targets --all-features -- -D warnings
	cargo test --all --all-features --quiet

ci-windows:
	rustup target add x86_64-pc-windows-gnu
	cargo check --all --all-features --target x86_64-pc-windows-gnu

ci-macos:
	rustup target add x86_64-apple-darwin aarch64-apple-darwin
	cargo check --all --all-features --target x86_64-apple-darwin
	cargo check --all --all-features --target aarch64-apple-darwin

ci-platforms:
	just ci-linux
	just ci-windows
	just ci-macos
