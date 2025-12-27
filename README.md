# rcman - Rust Config Manager

[![Crates.io](https://img.shields.io/crates/v/rcman.svg)](https://crates.io/crates/rcman)
[![Documentation](https://docs.rs/rcman/badge.svg)](https://docs.rs/rcman)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/Zarestia-Dev/rcman/workflows/CI/badge.svg)](https://github.com/Zarestia-Dev/rcman/actions)
[![MSRV](https://img.shields.io/badge/MSRV-1.70-blue)](https://github.com/rust-lang/rust/releases/tag/1.70.0)

A generic, **framework-agnostic** Rust library for managing application settings with backup/restore, sub-settings, and credential management.

> **Built with modern Rust best practices** — Comprehensive test coverage (143 tests), CI-enforced quality gates (fmt, clippy, cargo-deny), and production-ready error handling.

## Quick Links

- [📖 API Documentation](https://docs.rs/rcman)
- [📦 Crates.io](https://crates.io/crates/rcman)
- [💡 Examples](./examples)
- [📝 Changelog](./CHANGELOG.md)
- [🤝 Contributing](./CONTRIBUTING.md)

## Features

| Feature                 | Description                                              |
| ----------------------- | -------------------------------------------------------- |
| **Settings Management** | Load/save with rich schema metadata for UI rendering     |
| **Sub-Settings**        | Per-entity configs (e.g., one JSON per remote)           |
| **Backup & Restore**    | Encrypted ZIP backups with AES-256                       |
| **Secret Settings**     | Auto-routes secrets to OS keychain                       |
| **Env Var Overrides**   | Override settings via environment variables (Docker/K8s) |
| **Atomic Writes**       | Crash-safe file writes (temp file + rename)              |
| **Cross-Platform**      | Pure Rust - Windows, macOS, Linux, Android               |

---

## Installation

```toml
[dependencies]
rcman = "0.1"
```

### Feature Flags

| Feature          | Description                       | Default? |
| ---------------- | --------------------------------- | -------- |
| `json`           | JSON storage                      | ✅       |
| `backup`         | Backup/restore (zip)              | ✅       |
| `derive`         | `#[derive(SettingsSchema)]` macro | ❌       |
| `keychain`       | OS keychain support               | ❌       |
| `encrypted-file` | AES-256 encrypted file            | ❌       |
| `full`           | All features                      | ❌       |

**Examples:**

```toml
# Default (settings + backup)
rcman = "0.1"

# Minimal (just settings, no backup)
rcman = { version = "0.1", default-features = false, features = ["json"] }

# With OS keychain support
rcman = { version = "0.1", features = ["keychain"] }

# Everything
rcman = { version = "0.1", features = ["full"] }
```

---

## Quick Start

```rust
use rcman::{SettingsManager, SubSettingsConfig};

// Initialize with fluent builder API
let manager = SettingsManager::builder("my-app", "1.0.0")
    .config_dir("~/.config/my-app")
    .with_credentials()      // Enable automatic secret storage
    .with_env_prefix("MYAPP") // Enable env var overrides (MYAPP_UI_THEME=dark)
    .with_sub_settings(SubSettingsConfig::new("remotes"))  // Per-entity config
    .build()?;
```

---

## Core Concepts

### 1. Settings Schema with Builder Pattern

Define settings using the clean builder API:

```rust
use rcman::{settings, SettingsSchema, SettingMetadata, opt};

#[derive(Default, Serialize, Deserialize)]
struct AppSettings {
    dark_mode: bool,
    language: String,
    api_key: String,
}

impl SettingsSchema for AppSettings {
    fn get_metadata() -> HashMap<String, SettingMetadata> {
        settings! {
            // Toggle setting
            "ui.dark_mode" => SettingMetadata::toggle("Dark Mode", false)
                .category("appearance")
                .order(1),

            // Select with options
            "ui.language" => SettingMetadata::select("Language", "en", vec![
                opt("en", "English"),
                opt("tr", "Turkish"),
                opt("de", "German"),
            ]),

            // Number with range
            "ui.font_size" => SettingMetadata::number("Font Size", 14.0)
                .min(8.0).max(32.0).step(1.0),

            // Secret (auto-stored in keychain!)
            "api.key" => SettingMetadata::password("API Key", "")
                .secret(),

            // List of strings
            "network.allowed_ips" => SettingMetadata::list("Allowed IPs", vec!["127.0.0.1".to_string()])
                .description("IP addresses allowed to connect")
                .category("network"),
        }
    }
}
```

### Available Constructors

| Constructor                       | Description       |
| --------------------------------- | ----------------- |
| `text(label, default)`            | Text input        |
| `password(label, default)`        | Password input    |
| `number(label, default)`          | Number input      |
| `toggle(label, default)`          | Boolean toggle    |
| `select(label, default, options)` | Dropdown          |
| `color(label, default)`           | Color picker      |
| `path(label, default)`            | Directory path    |
| `file(label, default)`            | File path         |
| `list(label, default)`            | List of strings   |
| `info(label, default)`            | Read-only display |

### Chainable Setters

`.description()` `.min()` `.max()` `.step()` `.placeholder()` `.category()` `.order()` `.requires_restart()` `.advanced()` `.disabled()` `.secret()` `.pattern()` `.pattern_error()`

### Using the Derive Macro (Recommended)

Instead of implementing `SettingsSchema` manually, use the derive macro:

```toml
rcman = { version = "0.1", features = ["derive"] }
```

```rust
use rcman::DeriveSettingsSchema;
use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize, DeriveSettingsSchema)]
#[schema(category = "general")]
struct GeneralSettings {
    #[setting(label = "Enable Tray", description = "Show tray icon")]
    tray_enabled: bool,

    #[setting(label = "Port", min = 1024, max = 65535)]
    port: u16,

    #[setting(label = "Theme", options(("light", "Light"), ("dark", "Dark")))]
    theme: String,
}
```

**Available field attributes:**

- `label`, `description`, `category`
- `min`, `max`, `step` (for numbers)
- `options((...))` (for selects)
- `secret`, `advanced`, `requires_restart`, `skip`

---

### 2. Sub-Settings

Per-entity configuration files (e.g., one config per "remote"):

```rust
use rcman::{SettingsManager, SubSettingsConfig};
use serde_json::json;

// Register sub-settings via builder
let manager = SettingsManager::builder("my-app", "1.0.0")
    .with_sub_settings(SubSettingsConfig::new("remotes"))  // Multi-file mode
    .with_sub_settings(SubSettingsConfig::new("backends").single_file())  // Single-file mode
    .build()?;

// Access sub-settings
let remotes = manager.sub_settings("remotes")?;

// CRUD operations
remotes.set("gdrive", &json!({"type": "drive"}))?;
let gdrive_config = remotes.get::<serde_json::Value>("gdrive")?;
let all_remotes = remotes.list()?;
remotes.delete("onedrive")?;
```

**Storage Modes:**

| Mode                 | Files Created                            | Use Case                                  |
| -------------------- | ---------------------------------------- | ----------------------------------------- |
| Multi-file (default) | `remotes/gdrive.json`, `remotes/s3.json` | Large configs, many entities              |
| Single-file          | `backends.json`                          | Small collections, simpler file structure |

---

### 3. Secret Settings (Automatic Keychain Storage)

Settings marked with `.secret()` are automatically stored in the OS keychain:

```rust
// In schema
"api.key" => SettingMetadata::password("API Key", "")
    .secret(),

// Usage - automatically routes to keychain!
manager.save_setting::<MySettings>("api", "key", json!("sk-123"))?;
// → Stored in OS keychain, NOT in settings.json
```

**Backends:**

- macOS: Keychain
- Windows: Credential Manager
- Linux: Secret Service (via libsecret)
- **Fallback:** Encrypted file with Argon2id + AES-256-GCM

---

### 4. Backup & Restore

Create, analyze, and restore encrypted backups using the builder pattern:

```rust
use rcman::{BackupOptions, RestoreOptions};

// Create backup with builder pattern
let backup_path = manager.backup()
    .create(BackupOptions::new()
        .output_dir("./backups")
        .password("backup_password")
        .note("Weekly backup"))
    ?;

// Analyze a backup before restoring (inspect contents, check encryption)
let analysis = manager.backup().analyze(&backup_path)?;
println!("Encrypted: {}", analysis.requires_password);
println!("Valid: {}", analysis.is_valid);
println!("Created by app v{}", analysis.manifest.app_version);
if !analysis.warnings.is_empty() {
    println!("Warnings: {:?}", analysis.warnings);
}

// Restore with builder pattern
manager.backup()
    .restore(RestoreOptions::from_path(&backup_path)
        .password("backup_password")
        .overwrite(true))
    ?;
```

---

### 5. Default Value Behavior

When you save a setting that equals its default, rcman **removes it from storage**:

- **Regular settings**: Removed from JSON file
- **Secret settings**: Removed from keychain

This keeps files minimal and allows changing defaults in code to auto-apply to users.

```rust
# Save non-default value (stored)
manager.save_setting::<S>("ui", "theme", json!("dark"))?;

// Save default value (removed from storage)
manager.save_setting::<S>("ui", "theme", json!("light"))?;  // "light" is default

// Or use reset_setting() to explicitly reset
manager.reset_setting::<S>("ui", "theme")?;
```

---

### 6. Environment Variable Overrides

Override settings via environment variables for Docker/Kubernetes deployments:

```rust
// Enable with prefix
let config = SettingsConfig::builder("my-app", "1.0.0")
    .with_env_prefix("MYAPP")
    .build();
```

**Format:** `{PREFIX}_{CATEGORY}_{KEY}` (all uppercase)

| Setting Key     | Environment Variable       |
| --------------- | -------------------------- |
| `ui.theme`      | `MYAPP_UI_THEME=dark`      |
| `core.port`     | `MYAPP_CORE_PORT=9090`     |
| `general.debug` | `MYAPP_GENERAL_DEBUG=true` |

**Priority:** Env Var > Stored Value > Default

**Type Parsing:**

- `true`/`false` → boolean
- Numbers → i64/f64
- JSON → parsed as JSON
- Everything else → string

**UI Detection:**

```rust
let settings = manager.load_settings::<MySettings>()?;
for (key, meta) in settings {
    if meta.env_override {
        println!("🔒 {} is overridden by env var", key);
    }
}
```

> **Note:** Secret settings (stored in keychain) are NOT affected by env var overrides by default.
> To enable, use `.env_overrides_secrets(true)`:
>
> ```rust
> SettingsConfig::builder("my-app", "1.0.0")
>     .with_env_prefix("MYAPP")
>     .env_overrides_secrets(true)  // Allow MYAPP_API_KEY to override keychain
>     .build()
> ```

---

## Architecture

```
rcman/
├── config/
│   ├── types.rs      # SettingsConfig + Builder
│   └── schema.rs     # SettingMetadata + Builder, settings! macro
├── credentials/
│   ├── keychain.rs   # OS keychain backend
│   ├── encrypted.rs  # AES-256-GCM file backend
│   └── memory.rs     # Testing backend
├── backup/
│   ├── operations.rs # Create backups
│   ├── restore.rs    # Restore backups
│   └── archive.rs    # Zip utilities
├── manager.rs        # Main SettingsManager
├── storage.rs        # StorageBackend trait
└── sub_settings.rs   # Per-entity configs
```

---

## Performance

`rcman` is designed for efficiency:

- **In-Memory Caching**: Settings are cached after first load, eliminating redundant disk I/O
- **Defaults Cache**: Default values are cached to avoid repeated schema lookups
- **Sync I/O**: Simple, blocking file operations using `std::fs` (no runtime overhead)
- **Smart Writes**: Only writes to disk when values actually change
- **Zero-Copy Reads**: Uses `RwLock` for concurrent read access without cloning

**Benchmarks** (typical desktop app with 50 settings):

- First load: ~2ms (disk read + parse)
- Cached load: ~50μs (memory access)
- Save setting: ~1-3ms (validation + disk write)

---

## Error Handling

All operations return typed errors:

```rust
use rcman::{Error, Result};

match manager.save_setting::<MySettings>("ui", "theme", json!("dark")) {
    Ok(()) => println!("Saved!"),
    Err(Error::InvalidSettingValue { reason, .. }) => println!("Invalid: {}", reason),
    Err(e) => println!("Error: {}", e),
}
```

---

## Development

This project follows modern Rust library best practices. See [CONTRIBUTING.md](./CONTRIBUTING.md) for development guidelines.

### Quick Commands

```bash
# Run all checks (CI equivalent)
just fmt clippy test deny

# Individual commands
just fmt      # Format code
just clippy   # Run linter
just test     # Run tests
just docs     # Build docs
just deny     # Check dependencies
```

### Quality Standards

- **MSRV**: Rust 1.70+
- **Code Quality**: `clippy -D warnings` enforced in CI
- **Test Coverage**: 143 tests (120 passing + 13 performance + 10 environment)
- **Documentation**: Comprehensive doctests and API docs
- **Dependencies**: Audited via `cargo-deny` (licenses, advisories, duplicates)

### Pre-commit Hook (Optional)

```bash
git config core.hooksPath .githooks
chmod +x .githooks/pre-commit
```

---

## License

MIT
