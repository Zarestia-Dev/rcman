# rcman - Rust Config Manager

[![Crates.io](https://img.shields.io/crates/v/rcman.svg)](https://crates.io/crates/rcman)
[![Documentation](https://docs.rs/rcman/badge.svg)](https://docs.rs/rcman)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/Zarestia-Dev/rcman/workflows/CI/badge.svg)](https://github.com/Zarestia-Dev/rcman/actions)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue)](https://github.com/rust-lang/rust/releases/tag/1.85.0)

A generic, **framework-agnostic** Rust library for managing application settings with backup/restore, sub-settings, and credential management.

> **Built with modern Rust best practices** — Comprehensive test coverage, CI-enforced quality gates (fmt, clippy, cargo-deny), and production-ready error handling.

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
| **Profiles**            | Multiple named configurations (work, personal, etc.)     |
| **Schema Migration**    | Lazy migration for transparent data upgrades             |
| **Backup & Restore**    | Encrypted ZIP backups with AES-256                       |
| **Secret Settings**     | Auto-routes secrets to OS keychain                       |
| **External Configs**    | Include external files/commands in backups               |
| **Env Var Overrides**   | Override settings via environment variables (Docker/K8s) |
| **Atomic Writes**       | Crash-safe file writes (temp file + rename)              |
| **Cross-Platform**      | Pure Rust - Windows, macOS, Linux, Android               |

---

## Installation

```bash
cargo add rcman
```

### Feature Flags

| Feature          | Description                       | Default? |
| ---------------- | --------------------------------- | -------- |
| `json`           | JSON storage                      | ✅       |
| `toml`           | TOML storage                      | ❌       |
| `backup`         | Backup/restore (zip)              | ✅       |
| `derive`         | `#[derive(SettingsSchema)]` macro | ❌       |
| `keychain`       | OS keychain support               | ❌       |
| `encrypted-file` | AES-256 encrypted file            | ❌       |
| `profiles`       | Multiple named configurations     | ❌       |
| `full`           | All features                      | ❌       |

**Examples:**

```bash
# Default (settings + backup)
cargo add rcman

# Minimal (just settings, no backup)
cargo add rcman --no-default-features --features json

# With OS keychain support
cargo add rcman --features keychain

# Everything
cargo add rcman --features full
```

---

## Quick Start

### Choosing Your API Pattern

rcman offers two primary patterns depending on your needs:

#### 🎯 Type-Safe Pattern (Recommended)

Best for: Applications with a defined schema and need compile-time safety.

```rust
use rcman::{TypedManager, SettingsSchema, SettingMetadata, settings};
use serde::{Serialize, Deserialize};

#[derive(Default, Serialize, Deserialize)]
struct MySettings { theme: String }

impl SettingsSchema for MySettings {
    fn get_metadata() -> std::collections::HashMap<String, SettingMetadata> {
        settings! { "ui.theme" => SettingMetadata::text("Theme", "dark") }
    }
}

let manager = TypedManager::<MySettings>::builder("my-app", "1.0.0")
    .with_schema::<MySettings>()
    .build()?;

// Type-safe access!
let settings: MySettings = manager.settings()?;
```

#### 🔧 Dynamic Pattern

Best for: Plugins, dynamic configs, or when schema is defined externally.

```rust
use rcman::DynamicManager;

let manager = DynamicManager::builder("my-app", "1.0.0").build()?;

// Runtime access via HashMap
let settings = manager.load_settings()?;
```

> **📖 See [examples/api_patterns.rs](examples/api_patterns.rs) for comprehensive comparisons**

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

### 2.1 Profiles

Profiles let you maintain multiple named configurations. Enable with the `profiles` feature:

```bash
cargo add rcman --features profiles
```

#### Main Settings Profiles (App-Wide)

Enable profiles for your main `settings.json` to switch entire app configurations:

```rust
use rcman::SettingsManager;

let manager = SettingsManager::builder("my-app", "1.0.0")
    .with_profiles()  // Enable profiles for main settings
    .build()?;

// Profile management for main settings
manager.create_profile("work")?;
manager.switch_profile("work")?;
manager.active_profile()?  // "work"

// All settings are now isolated per profile
manager.save_setting::<MySettings>("ui", "theme", json!("dark"))?;
```

**Directory structure:**

```text
my-app/
├── .profiles.json
└── profiles/
    ├── default/
    │   └── settings.json
    └── work/
        └── settings.json
```

#### Sub-Settings Profiles

Enable profiles for specific sub-settings (e.g., different remote configs):

```rust
use rcman::{SettingsManager, SubSettingsConfig};
use serde_json::json;

// Enable profiles only for remotes
let manager = SettingsManager::builder("my-app", "1.0.0")
    .with_sub_settings(SubSettingsConfig::new("remotes").with_profiles())
    .build()?;

let remotes = manager.sub_settings("remotes")?;

// Add data to default profile
remotes.set("personal-gdrive", &json!({"type": "drive"}))?;

// Create and switch to work profile
remotes.profiles()?.create("work")?;
remotes.switch_profile("work")?;  // Seamless switch

// Now operations use the work profile
remotes.set("company-drive", &json!({"type": "sharepoint"}))?;

// Profile management
let profiles = remotes.profiles()?;
profiles.list()?;                            // ["default", "work"]
profiles.duplicate("work", "work-backup")?;  // Copy a profile
profiles.rename("work-backup", "archived")?; // Rename
profiles.delete("archived")?;                // Delete (can't delete active)
```

**Directory structure:**

```text
remotes/
├── .profiles.json
└── profiles/
    ├── default/
    │   └── gdrive.json
    └── work/
        └── company-drive.json
```

---

### 3. Schema Migration

Automatically upgrade old data formats when loading settings:

```rust
use rcman::{SettingsManager, SubSettingsConfig};
use serde_json::json;

// Main settings migration
let manager = SettingsManager::builder("my-app", "2.0.0")
    .with_migrator(|mut value| {
        // Upgrade v1 -> v2: rename "color" to "theme"
        if let Some(obj) = value.as_object_mut() {
            if let Some(ui) = obj.get_mut("ui").and_then(|v| v.as_object_mut()) {
                if let Some(color) = ui.remove("color") {
                    ui.insert("theme".to_string(), color);
                }
            }
        }
        value
    })
    .build()?;

// Sub-settings migration (per-entry for multi-file mode)
let remotes_config = SubSettingsConfig::new("remotes")
    .with_migrator(|mut value| {
        // Add version field to each remote
        if let Some(obj) = value.as_object_mut() {
            if !obj.contains_key("version") {
                obj.insert("version".into(), json!(2));
            }
        }
        value
    });

// Sub-settings migration (whole-file for single-file mode)
let backends_config = SubSettingsConfig::new("backends")
    .single_file()
    .with_migrator(|mut value| {
        // Migrate all backends at once
        if let Some(obj) = value.as_object_mut() {
            for (_name, backend) in obj.iter_mut() {
                if let Some(b) = backend.as_object_mut() {
                    b.insert("migrated".into(), json!(true));
                }
            }
        }
        value
    });
```

**How it works:**

1. Migrator runs automatically on first load after app update
2. If data changes, it's immediately written back to disk
3. Subsequent loads skip migration (no performance impact)
4. **Multi-file mode**: Migrator runs per-entry (each remote.json)
5. **Single-file mode**: Migrator runs on whole file (all entries at once)

---

### 4. Secret Settings (Automatic Keychain Storage)

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

### 5. Backup & Restore

Create, analyze, and restore encrypted backups using the builder pattern:

```rust
use rcman::{BackupOptions, RestoreOptions};

// Create full backup with builder pattern
let backup_path = manager.backup()
    .create(BackupOptions::new()
        .output_dir("./backups")
        .password("backup_password")
        .note("Weekly backup")
        .filename_suffix("full"))  // Custom filename: app_timestamp_full.rcman
    ?;

// Create partial backup (only specific sub-settings)
let remotes_backup = manager.backup()
    .create(BackupOptions::new()
        .output_dir("./backups")
        .export_type(ExportType::SettingsOnly)
        .include_settings(false)  // Don't include main settings
        .include_sub_settings("remotes")  // Only backup remotes
        .filename_suffix("remotes"))  // Creates: app_timestamp_remotes.rcman
    ?;

// Create backup for specific profiles (requires `profiles` feature)
#[cfg(feature = "profiles")]
let profile_backup = manager.backup()
    .create(BackupOptions::new()
        .output_dir("./backups")
        .include_profiles(vec!["work".to_string()]) // Only backup 'work' profile
        .filename_suffix("work_only"))
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

### 6. Default Value Behavior

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

### 7. Environment Variable Overrides

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

## Migration & Schema Evolution

rcman supports transparent schema migration for evolving your settings over time without breaking existing user configs.

### How Migration Works

Migrations run **lazily** on first settings load. If the migrator returns a modified value, rcman automatically saves the upgraded config.

### Basic Migration Example

```rust
use rcman::SettingsConfig;
use serde_json::Value;

let config = SettingsConfig::builder("my-app", "2.0.0")
    .with_migrator(|mut value| {
        // Runs once on load if config exists
        if let Some(obj) = value.as_object_mut() {
            // Example: Rename field
            if let Some(ui) = obj.get_mut("ui").and_then(|v| v.as_object_mut()) {
                if let Some(old_field) = ui.remove("color") {
                    ui.insert("theme".to_string(), old_field);
                }
            }

            // Example: Add new field with default
            if !obj.contains_key("features") {
                obj.insert("features".to_string(), serde_json::json!({
                    "telemetry": false
                }));
            }
        }
        value  // Return modified value
    })
    .build();
```

### Common Migration Patterns

#### 1. Renaming Settings

```rust
.with_migrator(|mut value| {
    if let Some(obj) = value.as_object_mut() {
        // Rename "network.timeout_ms" → "network.request_timeout"
        if let Some(net) = obj.get_mut("network").and_then(|v| v.as_object_mut()) {
            if let Some(timeout) = net.remove("timeout_ms") {
                net.insert("request_timeout".to_string(), timeout);
            }
        }
    }
    value
})
```

#### 2. Adding New Settings with Defaults

```rust
.with_migrator(|mut value| {
    if let Some(obj) = value.as_object_mut() {
        // Add new category if missing
        if !obj.contains_key("experimental") {
            obj.insert("experimental".to_string(), serde_json::json!({
                "beta_features": false,
                "debug_mode": false
            }));
        }
    }
    value
})
```

#### 3. Type Conversions

```rust
.with_migrator(|mut value| {
    if let Some(obj) = value.as_object_mut() {
        // Convert port from string to number
        if let Some(port) = obj.get("server").and_then(|v| v.get("port")) {
            if let Some(port_str) = port.as_str() {
                if let Ok(port_num) = port_str.parse::<u16>() {
                    obj.get_mut("server")
                        .and_then(|v| v.as_object_mut())
                        .map(|server| {
                            server.insert("port".to_string(), serde_json::json!(port_num));
                        });
                }
            }
        }
    }
    value
})
```

#### 4. Multi-Version Migrations

```rust
.with_migrator(|mut value| {
    // Check current schema version
    let version = value.get("_schema_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(1);

    if version < 2 {
        // Migrate v1 → v2
        if let Some(obj) = value.as_object_mut() {
            // ... migration logic ...
            obj.insert("_schema_version".to_string(), serde_json::json!(2));
        }
    }

    if version < 3 {
        // Migrate v2 → v3
        if let Some(obj) = value.as_object_mut() {
            // ... migration logic ...
            obj.insert("_schema_version".to_string(), serde_json::json!(3));
        }
    }

    value
})
```

### Profile-Specific Migrations

When using profiles, you can migrate all profiles automatically:

```rust
#[cfg(feature = "profiles")]
use rcman::profiles::ProfileMigrator;

let config = SettingsConfig::builder("my-app", "2.0.0")
    .enable_profiles(ProfileMigrator::Auto)  // Applies main migrator to all profiles
    .with_migrator(|mut value| {
        // This runs for main settings AND all profiles
        // ... migration logic ...
        value
    })
    .build();
```

### Testing Migrations

Always test your migrations with real user data:

```rust
#[test]
fn test_migration_v1_to_v2() {
    use serde_json::json;

    // Old format
    let old_config = json!({
        "ui": { "color": "dark" }
    });

    // Apply migration
    let migrator = |mut value: Value| {
        if let Some(obj) = value.as_object_mut() {
            if let Some(ui) = obj.get_mut("ui").and_then(|v| v.as_object_mut()) {
                if let Some(color) = ui.remove("color") {
                    ui.insert("theme".to_string(), color);
                }
            }
        }
        value
    };

    let new_config = migrator(old_config);

    // Verify
    assert_eq!(new_config["ui"]["theme"], "dark");
    assert!(new_config["ui"].get("color").is_none());
}
```

### Migration Best Practices

1. **Never delete data** - Rename or move instead
2. **Version your schema** - Use `_schema_version` field to track changes
3. **Test with real data** - Use copies of actual user configs
4. **Document breaking changes** - In CHANGELOG.md and migration comments
5. **Keep migrations forever** - Users might upgrade from any version
6. **One-way only** - Don't try to support downgrade paths
7. **Fail gracefully** - Log errors, don't crash on migration failure

### Migration Logging

```rust
.with_migrator(|mut value| {
    log::info!("Running schema migration to v2.0.0");

    // ... migration logic ...

    log::info!("Migration completed successfully");
    value
})
```

### Testing With Environment Variables

rcman uses dependency injection for env vars, making tests clean:

```rust
use rcman::{EnvSource, MockEnvSource};

let mock_env = Arc::new(MockEnvSource::new());
mock_env.set("MYAPP_THEME", "dark");

let config = SettingsConfig::builder("my-app", "1.0")
    .with_env_source(mock_env)
    .build();
```

---

## Performance

- **In-Memory Caching**: Reads are O(1) after first load.
- **Lazy Computation**: Merged views are computed only when needed.
- **Smart Writes**: Disk I/O only occurs when values actually change.
- **Configurable Caching**: Choose between `Full`, `LRU`, or `None` strategies for sub-settings.

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
cargo fmt -- --check      # Format code
cargo clippy -- -D clippy::all   # Run linter
cargo test -- --test-threads=1   # Run tests
cargo test docs     # Build docs
cargo deny check     # Check dependencies
```

### Quality Standards

- **MSRV**: Rust 1.70+
- **Code Quality**: `clippy -D warnings` enforced in CI
- **Test Coverage**: Comprehensive test suite with unit, integration, and edge case tests
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
