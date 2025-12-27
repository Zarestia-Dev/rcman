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

docs:
	RUSTDOCFLAGS="--cfg docsrs" cargo doc --all-features --no-deps

deny:
	cargo deny check
