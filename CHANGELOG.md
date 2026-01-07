# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **Lock Poisoning Recovery System**
  - sync.rs module with `RwLockExt` and `MutexExt` traits
  - Graceful handling of poisoned locks with `read_recovered()`, `write_recovered()`, `lock_recovered()`
  - Comprehensive tests for poison recovery scenarios

- **Atomic Cache Generation Counters** 
  - `AtomicU64` generation counters in `SettingsManager` for race-free cache invalidation
  - Lock-free concurrent cache invalidation detection

- **Secure File Permissions (Unix)**
  - security.rs module with permission enforcement
  - `set_secure_file_permissions()` - 0o600 (owner read/write only)
  - `set_secure_dir_permissions()` - 0o700 (owner rwx only)
  - Applied in storage.rs, sub_settings.rs, and profile managers

- **Profile Support** (new `profiles` feature)
  - profiles module with `ProfileManager`, `ProfileMigrator`
  - Profile CRUD operations (create, switch, delete, rename, duplicate)
  - Auto-migration from flat structure to `profiles/default/`
  - Profile-scoped sub-settings and main settings
  - Profile event system with callbacks
  - profiles_usage.rs demonstrating profile workflows

- **Tests**
  - profile_backup_restore.rs - Profile backup/restore integration tests
  - profiles_test.rs - Comprehensive profile CRUD and switching tests
  - sync.rs unit tests for poison recovery

### Changed

- **Deadlock Prevention in Profile Switching**
  - Refactored `SettingsManager::switch_profile()` to release locks before next acquisition
  - No nested lock holdings across manager, settings_dir, and sub_settings

- **Performance Optimization in SubSettings**
  - Optimized `single_file_path()` and `entry_path()` with inline path construction
  - Eliminated intermediate `get_base_dir()` allocations
  - Direct lock access + path join in single operation

- **Enhanced Error Handling**
  - `SubSettings::new()` fails fast on migration errors with clear messages
  - Profile migrator properly propagates serialization errors (removed `unwrap()`)
  - Added `MigrationFn` type alias for cleaner signatures

- **All Lock Operations Use Poison Recovery**
  - 62 lock acquisitions converted from `.unwrap()` to `.read_recovered()`/`.write_recovered()`
  - Consistent error handling across all modules

### Fixed

- **File permissions security** - All configuration files/directories created with secure permissions
- **Clippy warnings** - Fixed `type_complexity`, `derivable_impls`, unused variables
- **Edge case test** - Updated readonly directory test to properly verify permission enforcement


## [v0.1.1] - 2026-01-2

### Added

- **Efficient Settings Access API**
    - `get<T>(key)` - Single value access by key path (e.g., `manager.get::<bool>("general.restrict")`)
    - `get_value(key)` - Raw JSON value access by key path
    - `settings<T>()` - Merged settings struct with caching (replaces `load_startup`)
    - `merged_settings_cache` - Internal cache for merged settings to avoid repeated merge operations
- **Cache Efficiency Improvements**
    - In-place cache updates: `save_setting()` now updates merged cache in-place instead of invalidating
    - Lazy defaults cache: Only populated on first access, not overwritten on every `load_settings()` call
- **Sub-Settings Performance**
    - **SingleFile Mode**: Loads entire file into memory once. `get`, `list`, `exists` are now in-memory operations (instant).
    - **MultiFile Mode**: Lazily caches entries on access/write. Subsequent reads are instant.
    - Optimized `set` and `delete` to update cache immediately, avoiding read-after-write.
- **Documentation Improvements**
    - Enhanced `backup/archive.rs` module with comprehensive docs and format explanation
- **Testing Improvements**
    - Added derive macro integration tests (`tests/derive_macro_test.rs`) with 7 test cases
- **Lazy Migration System** for transparent schema upgrades
    - `with_migrator()` on `SettingsConfig` for main settings migration
    - `with_migrator()` on `SubSettingsConfig` for sub-settings migration
    - Automatic detection and persistence of migrated data
    - Supports both single-file and multi-file sub-settings modes
    - Example: Rename fields, add version numbers, restructure data transparently
- **Enhanced External Config System** for flexible backup/restore
    - `ExportSource` enum: Export from `File`, `Command` output, or `Content` (in-memory)
    - `ImportTarget` enum: Restore to `File`, pipe to `Command`, use custom `Handler`, or `ReadOnly`
    - `from_command()` and `from_content()` constructors for `ExternalConfig`
    - Command-based exports (e.g., `rclone config dump`)
    - Custom restore handlers for complex logic
    - Read-only configs for diagnostics and logs
- **Polymorphic Backup Manifest** for sub-settings
    - `SubSettingsManifestEntry` enum: `SingleFile(String)` or `MultiFile(Vec<String>)`
    - Proper handling of single-file vs multi-file sub-settings in backups
    - `sub_settings_list()` helper method on `BackupContents`
- **Custom Backup Filenames**
    - `filename_suffix` option in `BackupOptions` for custom naming
    - Smart inference: single sub-setting exports use category name
    - Format: `{app}_{timestamp}_{suffix}.rcman`
- `File` setting type for file path selection (distinct from `Path`)
- `List` setting type for managing arrays of strings (`Vec<String>`)
    - Constructor: `SettingMetadata::list(label, default)` for creating list settings
    - Automatic support in derive macro for `Vec<String>` fields
    - Example usage in `examples/list_settings.rs`, `examples/basic_usage.rs`, and `examples/derive_usage.rs`
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

- Comprehensive doctests for `JsonStorage`, `SettingMetadata`, and `SettingsManager`
- Module-level documentation improvements

### Changed

- **BREAKING**: Removed `load_startup<T>()` method - use `settings<T>()` instead
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
