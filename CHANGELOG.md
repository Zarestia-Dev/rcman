# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

**Testing & Quality**
- Comprehensive test suite with 143 tests total
  - 50 unit tests covering all core functionality
  - 70 integration tests for real-world workflows
  - 27 edge case tests (invalid inputs, concurrent access, corrupted files)
  - 11 performance/stress tests (1000+ entity operations, high concurrency)
  - 18 doctests with runnable examples
- `File` setting type for file path selection (distinct from `Path`)
- Edge case testing for type validation, concurrent operations, and special values

**Development Infrastructure**
- GitHub Actions CI/CD pipeline enforcing fmt, clippy -D warnings, tests, and cargo-deny
- MSRV 1.70 declared with `rust-toolchain.toml` for consistent toolchain
- `clippy.toml` with MSRV-aware linting configuration
- `cargo-deny` setup for license compatibility, security advisories, and dependency auditing
- `justfile` with common development tasks (fmt, clippy, test, docs, deny)
- `.editorconfig` for consistent code formatting across editors
- Optional pre-commit git hook for automatic clippy checks
- Comprehensive `CONTRIBUTING.md` with development workflow guide

**Documentation**
- Feature-gated API documentation for docs.rs using `#[cfg_attr(docsrs, doc(cfg(...)))]`
- Comprehensive doctests for `JsonStorage`, `SettingMetadata`, and `SettingsManager`
- Module-level documentation improvements

### Changed

- `save_setting` now enforces strict schema validation (rejects undefined keys)
- Event system now recovers from poisoned locks (`unwrap_or_else(|e| e.into_inner())`) to avoid panics in multi-threaded environments
- All clippy warnings resolved across library, examples, and tests

### Fixed

- `reset_all` now correctly clears credentials from the secure backend
- Empty line formatting after `#[cfg]` attributes in examples
- Clippy warnings in test code (derivable impls, blocks in conditions)

## [0.1.0] - 2025-12-26

### Added

**Core Features**

- Settings management with JSON storage and in-memory caching
- Schema-based configuration with rich metadata for UI rendering
  - Type-specific constructors: `text()`, `number()`, `toggle()`, `select()`, `password()`, `color()`, `path()`, `info()`
  - Chainable setters: `description()`, `min()`, `max()`, `step()`, `category()`, `order()`, `advanced()`, `disabled()`, `secret()`
  - Pattern validation with regex and `pattern_error()` for custom messages
- Sub-settings for per-entity configuration files
  - Multi-file mode: `remotes/gdrive.json`, `remotes/s3.json`
  - Single-file mode: `backends.json` with all entities as keys
- Event system for change notifications and validation hooks

**Backup & Restore**

- Encrypted backups with ZIP format (AES-256)
- Granular backup selection: `include_sub_settings_items()`, `include_external()`
- `ExportCategory` and `ExportCategoryType` for UI category discovery
- `get_export_categories()` on `SettingsManager`
- Backup manifest with checksums, `analyze()` for pre-restore inspection
- External configuration registration via `with_external_config()`

**Credential Management**

- OS keychain integration (macOS Keychain, Windows Credential Manager, Linux Secret Service)
- Encrypted file fallback with Argon2id
- Mark settings with `.secret()` for automatic keychain storage

**Environment Variable Overrides**

- `with_env_prefix()` to enable env var overrides
- `env_overrides_secrets(true)` for Docker/CI environments
- Format: `{PREFIX}_{CATEGORY}_{KEY}` (e.g., `MYAPP_UI_THEME=dark`)
- Priority: Env Var > Stored Value > Default
- `env_override` flag in `SettingMetadata` for UI display

### Security

- Argon2id key derivation - State-of-the-art protection against GPU brute-force
- Atomic file writes (temp file + rename) to prevent corruption
- Mutex locks on save operations to prevent race conditions
- No secret values logged in any log statements
- Secrets removed from storage when set to default value
