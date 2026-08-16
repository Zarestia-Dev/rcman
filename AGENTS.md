# AGENTS.md

This file provides guidance to AI coding agents (e.g. Antigravity, Claude Code, Gemini CLI, Cursor, and similar tools) when working with code in this repository.

`rcman` welcomes AI-assisted contributions, but the expectation is that you, the human submitter, understand every line you propose and have compiled, linted, and tested it against real code — not just generated it. See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

---

## Project Overview

`rcman` is a framework-agnostic settings management library in Rust featuring schema validation, backup/restore, OS keychain / encrypted-file secrets, sub-settings, and named profiles.

- **Workspace Members**:
  - `rcman`: Core settings engine, storage backends (JSON, TOML, YAML, SQLite), credential management, backup/restore, profiles, and sub-settings.
  - `rcman-derive`: Procedural derive macro crate providing `#[derive(SettingsSchema)]` and compile-time schema validation.

---

## General Notes & AI Guidelines

1. **Keep Changes Minimal & Elegant**: Work to make the smallest, most effective change possible. Avoid unneeded refactoring, re-ordering of imports, or restyling surrounding code.
2. **Backwards Compatibility**: PRs must preserve existing configuration schema formats, migration paths, and storage backend guarantees across desktop (Linux, macOS, Windows) and mobile (Android, iOS) targets.
3. **Verify Before Proposing**: AI agents must run build, clippy, test, and formatting verification commands across all features before declaring success. All checks must complete with **zero errors and zero warnings**.

---

## Essential Architectural Rules

1. **Deterministic Metadata Ordering (CRITICAL)**
   - **ALWAYS** use `indexmap::IndexMap` (re-exported as `rcman::IndexMap`) for setting metadata maps (`SettingsSchema::get_metadata()`, `SettingsManager::metadata()`, and `SubSettings::schema_metadata()`).
   - **DO NOT** use `std::collections::HashMap` for metadata, as its randomized hash seed destroys declaration order and causes non-deterministic UI and serialization output.

2. **Secret Handling & Keychain Isolation**
   - Fields marked with `.secret()` or `#[setting(secret)]` must **never** be written to disk in plain text settings files.
   - When saving settings equal to their default value, `rcman` removes them from storage and keychain to keep files and stores minimal.

3. **Derive Macro Hygiene (`rcman-derive`)**
   - Maintain compile-time error reporting with `syn::Error` spans (no runtime panics in procedural macros).
   - Ensure `#[cfg(...)]` attributes on struct fields are forwarded properly to generated metadata entries and typed accessor methods.

4. **Zero-Warning Code Quality**
   - Any new code must compile under `cargo clippy --all-targets --all-features -- -D warnings` without any suppressed warnings unless explicitly justified.

---

## CI & Automated Workflows ([.github/workflows/ci.yml](.github/workflows/ci.yml))

All changes proposed by AI agents must pass the checks enforced by our GitHub Actions workflows:

- **Build & Test Matrix**: Ubuntu, Windows, macOS running formatting checks, Clippy, and test suites.
- **Cross-Compilation**: Verifying target compilation for Windows GNU, macOS Darwin (x86_64, aarch64), Android, and iOS.
- **Cargo Deny**: Verifying dependency licenses and banned crates.

---

## Build, Test & Lint Commands

The commands below mirror the exact validation checks executed in [.github/workflows/ci.yml](.github/workflows/ci.yml) and the local [justfile](justfile).

### 1. Build & Compilation Check

```bash
# Check compilation across all workspace members and features
cargo check --all-targets --all-features
```

### 2. Formatting & Linting

```bash
# Check code formatting
cargo fmt --all -- --check

# Format all workspace code
cargo fmt --all

# Run Clippy across all targets and features (zero warnings allowed)
cargo clippy --all-targets --all-features -- -D warnings

# Check clippy pedantic on full feature set
cargo clippy --features full -- -W clippy::pedantic
```

### 3. Testing

```bash
# Run standard test suite across all features
cargo test --all --all-features

# Run all tests including ignored tests (requires Secret Service daemon on Linux)
cargo test --all-features --tests -- --include-ignored
```

### 4. Justfile Shortcuts

```bash
# Run standard CI verification locally
just ci-ubuntu

# Run full cross-target preflight check
just ci-local
```
