// GUI Demo for rcman - Interactive Settings Panel
//
// Run with: cargo run --example gui_demo
// With keychain: cargo run --example gui_demo --features keychain
//
// This example demonstrates how rcman works visually:
// - Loading settings from schema
// - Editing settings with appropriate controls
// - Validation feedback
// - Default value behavior (reset removes from storage)
// - Secret settings (stored in keychain)
// - Backup & Restore (encrypted and normal)
// - Real-time save/load

use eframe::egui;
use rcman::{
    BackupOptions, RestoreOptions, SettingMetadata, SettingsConfig, SettingsManager,
    SettingsSchema, SubSettingsConfig, opt, settings,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

// ============================================================================
// SETTINGS SCHEMA - Define your settings here
// ============================================================================

#[derive(Default, Serialize, Deserialize, Clone)]
struct DemoSettings;

impl SettingsSchema for DemoSettings {
    fn get_metadata() -> HashMap<String, SettingMetadata> {
        settings! {
            // App settings
            "app.name" => SettingMetadata::text("App Name", "My App")
                .description("Application name")
                .category("General")
                .order(1),

            "app.theme" => SettingMetadata::select("Theme", "light", vec![
                opt("light", "☀️ Light"),
                opt("dark", "🌙 Dark"),
                opt("auto", "🔄 Auto"),
            ])
                .description("Application color theme")
                .category("Appearance")
                .order(2),

            "app.font_size" => SettingMetadata::number("Font Size", 14.0)
                .description("Base font size in pixels")
                .min(8.0)
                .max(32.0)
                .step(1.0)
                .category("Appearance")
                .order(3),

            "app.animations" => SettingMetadata::toggle("Enable Animations", true)
                .description("Show smooth animations and transitions")
                .category("Appearance")
                .order(4),

            // Network settings
            "network.timeout" => SettingMetadata::number("Timeout (seconds)", 30.0)
                .description("Network request timeout")
                .min(5.0)
                .max(300.0)
                .step(5.0)
                .category("Network")
                .order(1),

            "network.retries" => SettingMetadata::number("Max Retries", 3.0)
                .description("Number of retry attempts on failure")
                .min(0.0)
                .max(10.0)
                .step(1.0)
                .category("Network")
                .order(2),

            // User settings (with validation)
            "user.email" => SettingMetadata::text("Email", "")
                .description("Your email address")
                .pattern(r"^$|^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
                .pattern_error("Please enter a valid email address")
                .placeholder("user@example.com")
                .category("User")
                .order(1),

            "user.username" => SettingMetadata::text("Username", "")
                .description("3-20 alphanumeric characters")
                .pattern(r"^$|^[a-zA-Z0-9_]{3,20}$")
                .pattern_error("Username must be 3-20 alphanumeric characters")
                .category("User")
                .order(2),

            // Secret settings (stored in keychain when feature enabled)
            "secrets.api_key" => {
                #[allow(unused_mut)]
                let mut s = SettingMetadata::password("API Key", "")
                    .description("Your API key (stored in keychain)")
                    .category("Secrets")
                    .order(1);
                #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
                {
                    s = s.secret();
                }
                s
            },

            "secrets.db_password" => {
                #[allow(unused_mut)]
                let mut s = SettingMetadata::password("Database Password", "")
                    .description("Database password (stored in keychain)")
                    .category("Secrets")
                    .order(2);
                #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
                {
                    s = s.secret();
                }
                s
            },

            // Advanced settings
            "advanced.debug" => SettingMetadata::toggle("Debug Mode", false)
                .description("Enable verbose logging")
                .category("Advanced")
                .advanced(),
        }
    }
}

// ============================================================================
// GUI STATES
// ============================================================================

struct DemoUiState {
    status_message: String,
    show_json: bool,
    current_json: String,
    show_api_key: bool,
    show_db_password: bool,
}

impl Default for DemoUiState {
    fn default() -> Self {
        Self {
            status_message: "✅ Settings loaded".to_string(),
            show_json: false,
            current_json: String::new(),
            show_api_key: false,
            show_db_password: false,
        }
    }
}

struct DemoSettingsState {
    app_name: String,
    theme: String,
    font_size: f64,
    animations: bool,
    timeout: f64,
    retries: f64,
    email: String,
    username: String,
    api_key: String,
    db_password: String,
    debug: bool,
}

impl Default for DemoSettingsState {
    fn default() -> Self {
        Self {
            app_name: "My App".to_string(),
            theme: "light".to_string(),
            font_size: 14.0,
            animations: true,
            timeout: 30.0,
            retries: 3.0,
            email: String::new(),
            username: String::new(),
            api_key: String::new(),
            db_password: String::new(),
            debug: false,
        }
    }
}

#[derive(Default)]
struct BackupState {
    password: String,
    note: String,
    use_encryption: bool,
    last_path: Option<PathBuf>,
    list: Vec<PathBuf>,
    selected_index: Option<usize>,
    restore_password: String,
    restore_requires_password: bool,
    analysis: Option<String>,
}

struct RemotesState {
    list: Vec<String>,
    new_name: String,
    new_type: String,
    selected: Option<String>,
    selected_data: String,
}

impl Default for RemotesState {
    fn default() -> Self {
        Self {
            list: Vec::new(),
            new_name: String::new(),
            new_type: "drive".to_string(),
            selected: None,
            selected_data: String::new(),
        }
    }
}

// ============================================================================
// GUI APPLICATION
// ============================================================================

struct DemoApp {
    manager: Arc<SettingsManager<rcman::storage::JsonStorage, DemoSettings>>,
    keychain_enabled: bool,
    encrypted_backend_status: String,
    settings: DemoSettingsState,
    ui: DemoUiState,
    backup: BackupState,
    remotes: RemotesState,
}

impl DemoApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        // Check if keychain feature is available
        let keychain_enabled = cfg!(feature = "keychain");

        // Detect encrypted backend status
        let encrypted_backend_status = if cfg!(feature = "encrypted-file") {
            let path = std::path::Path::new("./example_config/credentials.enc.json");
            if path.exists() {
                format!("Active (Argon2id v3)\nPath: {}", path.display())
            } else {
                "Enabled (Argon2id v3) - Waiting for secrets".to_string()
            }
        } else {
            "Disabled (enable 'encrypted-file' feature)".to_string()
        };

        // Initialize settings manager
        let config_builder = SettingsConfig::builder("rcman-gui-demo", "1.0.0")
            .with_schema::<DemoSettings>()
            .with_config_dir("./example_config");

        // Enable credentials if keychain feature is available
        #[cfg(feature = "keychain")]
        let config = config_builder.with_credentials().build();
        #[cfg(not(feature = "keychain"))]
        let config = config_builder.build();

        let manager = Arc::new(SettingsManager::new(config).expect("Failed to create manager"));

        let mut app = Self {
            manager,
            keychain_enabled,
            encrypted_backend_status,
            settings: DemoSettingsState::default(),
            ui: DemoUiState::default(),
            backup: BackupState::default(),
            remotes: RemotesState::default(),
        };

        // Load initial settings
        app.load_settings_values();

        // Scan for existing backups
        app.backup.list = Self::scan_backups();

        // Register sub-settings for remotes and load list
        app.remotes.list = {
            app.manager
                .register_sub_settings(SubSettingsConfig::new("remotes"))
                .unwrap();

            // Load remotes list
            match app.manager.sub_settings("remotes") {
                Ok(sub) => sub.list().unwrap_or_default(),
                Err(_) => Vec::new(),
            }
        };

        app
    }

    fn load_settings_values(&mut self) {
        let settings = { self.manager.metadata().unwrap_or_default() };
        let get_value = |key: &str| -> Value {
            settings
                .get(key)
                .and_then(|m| m.value.clone())
                .unwrap_or(Value::Null)
        };

        self.settings.app_name = get_value("app.name")
            .as_str()
            .unwrap_or("My App")
            .to_string();
        self.settings.theme = get_value("app.theme")
            .as_str()
            .unwrap_or("light")
            .to_string();
        self.settings.font_size = get_value("app.font_size").as_f64().unwrap_or(14.0);
        self.settings.animations = get_value("app.animations").as_bool().unwrap_or(true);
        self.settings.timeout = get_value("network.timeout").as_f64().unwrap_or(30.0);
        self.settings.retries = get_value("network.retries").as_f64().unwrap_or(3.0);
        self.settings.email = get_value("user.email").as_str().unwrap_or("").to_string();
        self.settings.username = get_value("user.username")
            .as_str()
            .unwrap_or("")
            .to_string();
        self.settings.api_key = get_value("secrets.api_key")
            .as_str()
            .unwrap_or("")
            .to_string();
        self.settings.db_password = get_value("secrets.db_password")
            .as_str()
            .unwrap_or("")
            .to_string();
        self.settings.debug = get_value("advanced.debug").as_bool().unwrap_or(false);

        self.update_json_view();
    }

    fn scan_backups() -> Vec<PathBuf> {
        let backup_dir = PathBuf::from("./example_config/backups");
        if !backup_dir.exists() {
            return Vec::new();
        }
        std::fs::read_dir(&backup_dir)
            .map(|entries| {
                entries
                    .filter_map(std::result::Result::ok)
                    .map(|e| e.path())
                    .filter(|p| p.extension().is_some_and(|e| e == "rcman"))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn create_backup(&mut self) {
        let manager = self.manager.clone();
        let password = if self.backup.use_encryption && !self.backup.password.is_empty() {
            Some(self.backup.password.clone())
        } else {
            None
        };
        let note = if self.backup.note.is_empty() {
            None
        } else {
            Some(self.backup.note.clone())
        };

        let res = {
            let mut options = BackupOptions::new().output_dir("./example_config/backups");
            if let Some(pw) = password {
                options = options.password(pw);
            }
            if let Some(n) = note {
                options = options.note(n);
            }
            manager.backup().create(&options)
        };
        match res {
            Ok(path) => {
                let encrypted = if self.backup.use_encryption && !self.backup.password.is_empty() {
                    " (encrypted)"
                } else {
                    ""
                };
                self.ui.status_message = format!(
                    "📦 Backup created{}: {:?}",
                    encrypted,
                    path.file_name().unwrap_or_default()
                );
                self.backup.last_path = Some(path);
                self.backup.list = Self::scan_backups();
            }
            Err(e) => {
                self.ui.status_message = format!("❌ Backup failed: {e}");
            }
        }
    }

    fn restore_backup(&mut self) {
        let Some(index) = self.backup.selected_index else {
            self.ui.status_message = "❌ No backup selected".to_string();
            return;
        };
        let Some(backup_path) = self.backup.list.get(index).cloned() else {
            self.ui.status_message = "❌ Invalid backup selection".to_string();
            return;
        };

        let manager = self.manager.clone();
        let password = if self.backup.restore_password.is_empty() {
            None
        } else {
            Some(self.backup.restore_password.clone())
        };

        let res = {
            let mut options = RestoreOptions::from_path(&backup_path)
                .overwrite(true)
                .verify_checksum(true);
            if let Some(pw) = password {
                options = options.password(pw);
            }
            manager.backup().restore(&options)
        };
        match res {
            Ok(_) => {
                self.ui.status_message = "✅ Backup restored successfully!".to_string();
                self.reload_settings();
            }
            Err(e) => {
                self.ui.status_message = format!("❌ Restore failed: {e}");
            }
        }
    }

    fn analyze_backup(&mut self) {
        let Some(index) = self.backup.selected_index else {
            self.ui.status_message = "❌ No backup selected".to_string();
            return;
        };
        let Some(backup_path) = self.backup.list.get(index).cloned() else {
            self.ui.status_message = "❌ Invalid backup selection".to_string();
            return;
        };

        let manager = self.manager.clone();
        match manager.backup().analyze(&backup_path) {
            Ok(analysis) => {
                let info = format!(
                    "📋 Backup Analysis:\n\
                     ├─ Valid: {}\n\
                     ├─ Encrypted: {}\n\
                     ├─ App Version: {}\n\
                     ├─ Manifest Version: {}\n\
                     └─ Warnings: {}",
                    if analysis.is_valid {
                        "✅ Yes"
                    } else {
                        "❌ No"
                    },
                    if analysis.requires_password {
                        "🔒 Yes"
                    } else {
                        "🔓 No"
                    },
                    analysis.manifest.backup.app_version,
                    analysis.manifest.version,
                    if analysis.warnings.is_empty() {
                        "None".to_string()
                    } else {
                        analysis.warnings.join(", ")
                    }
                );
                self.backup.analysis = Some(info);
                self.backup.restore_requires_password = analysis.requires_password;
                self.ui.status_message = "✅ Backup analyzed".to_string();
            }
            Err(e) => {
                self.backup.analysis = None;
                self.backup.restore_requires_password = false;
                self.ui.status_message = format!("❌ Analysis failed: {e}");
            }
        }
    }

    fn refresh_remotes(&mut self) {
        let manager = self.manager.clone();
        match (|| -> rcman::Result<_> {
            let sub = manager.sub_settings("remotes")?;
            sub.list()
        })() {
            Ok(list) => {
                self.remotes.list = list;
                self.ui.status_message = format!("📂 Found {} remotes", self.remotes.list.len());
            }
            Err(e) => {
                self.ui.status_message = format!("❌ Failed to load remotes: {e}");
            }
        }
    }

    fn add_remote(&mut self) {
        if self.remotes.new_name.is_empty() {
            self.ui.status_message = "❌ Remote name cannot be empty".to_string();
            return;
        }

        let manager = self.manager.clone();
        let name = self.remotes.new_name.clone();
        let remote_type = self.remotes.new_type.clone();

        match (|| -> rcman::Result<_> {
            let sub = manager.sub_settings("remotes")?;
            sub.set(
                &name,
                &json!({
                    "type": remote_type
                }),
            )
        })() {
            Ok(()) => {
                self.ui.status_message = format!("✅ Added remote: {}", self.remotes.new_name);
                self.remotes.new_name.clear();
                self.refresh_remotes();
            }
            Err(e) => {
                self.ui.status_message = format!("❌ Failed to add remote: {e}");
            }
        }
    }

    fn delete_remote(&mut self, name: &str) {
        let manager = self.manager.clone();
        let remote_name = name.to_string();

        match (|| -> rcman::Result<_> {
            let sub = manager.sub_settings("remotes")?;
            sub.delete(&remote_name)
        })() {
            Ok(()) => {
                self.ui.status_message = format!("🗑️ Deleted remote: {name}");
                self.remotes.selected = None;
                self.remotes.selected_data.clear();
                self.refresh_remotes();
            }
            Err(e) => {
                self.ui.status_message = format!("❌ Failed to delete remote: {e}");
            }
        }
    }

    fn load_remote_data(&mut self, name: &str) {
        let manager = self.manager.clone();
        let remote_name = name.to_string();

        match (|| -> rcman::Result<_> {
            let sub = manager.sub_settings("remotes")?;
            sub.get::<Value>(&remote_name)
        })() {
            Ok(data) => {
                self.remotes.selected_data =
                    serde_json::to_string_pretty(&data).unwrap_or_default();
            }
            Err(e) => {
                self.remotes.selected_data = format!("Error: {e}");
            }
        }
    }

    fn save_setting(&mut self, category: &str, key: &str, value: &Value) {
        let manager = self.manager.clone();
        match manager.save_setting(category, key, value) {
            Ok(()) => {
                self.ui.status_message = format!("✅ Saved {category}.{key}");
            }
            Err(e) => {
                self.ui.status_message = format!("❌ Error: {e}");
            }
        }
        self.update_json_view();
    }

    fn reset_setting(&mut self, category: &str, key: &str) {
        let manager = self.manager.clone();
        match manager.reset_setting(category, key) {
            Ok(default_value) => {
                self.ui.status_message =
                    format!("🔄 Reset {category}.{key} to default: {default_value}");
            }
            Err(e) => {
                self.ui.status_message = format!("❌ Error: {e}");
            }
        }
        self.reload_settings();
    }

    fn reload_settings(&mut self) {
        self.load_settings_values();
        self.ui.status_message = "✅ Settings reloaded".to_string();
    }

    fn update_json_view(&mut self) {
        let path = self.manager.config().settings_path();
        self.ui.current_json = std::fs::read_to_string(&path).unwrap_or_else(|_| "{}".to_string());
    }
}

// ============================================================================
// UI IMPLEMENTATION
// ============================================================================

impl eframe::App for DemoApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Apply theme
        if self.settings.theme == "dark" {
            ctx.set_visuals(egui::Visuals::dark());
        } else {
            ctx.set_visuals(egui::Visuals::light());
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("🔧 rcman GUI Demo");
            ui.label("Interactive demonstration of the rcman settings library");

            self.ui_status_status(ui);
            ui.add_space(8.0);

            egui::ScrollArea::vertical().show(ui, |ui| {
                self.ui_app_settings(ui);
                ui.add_space(8.0);
                self.ui_network_settings(ui);
                ui.add_space(8.0);
                self.ui_user_settings(ui);
                ui.add_space(8.0);
                self.ui_secrets_settings(ui);
                ui.add_space(8.0);
                self.ui_advanced_settings(ui);
                ui.add_space(8.0);
                self.ui_remotes_settings(ui);
                ui.add_space(8.0);
                self.ui_backup_settings(ui);

                // JSON VIEW
                if self.ui.show_json {
                    ui.add_space(16.0);
                    ui.separator();
                    ui.heading("📄 settings.json (actual file contents)");
                    ui.label(
                        egui::RichText::new(
                            "Only non-default values are stored! Secrets go to keychain!",
                        )
                        .small()
                        .weak(),
                    );
                    ui.add_space(4.0);

                    egui::ScrollArea::vertical()
                        .max_height(200.0)
                        .show(ui, |ui| {
                            ui.add(
                                egui::TextEdit::multiline(&mut self.ui.current_json.clone())
                                    .code_editor()
                                    .desired_width(f32::INFINITY),
                            );
                        });
                }

                // HELP SECTION
                ui.add_space(16.0);
                ui.separator();
                ui.collapsing("❓ How rcman Works", |ui| {
                    ui.label("• Settings are defined via SettingsSchema trait");
                    ui.label("• Each setting has a type, default value, and metadata");
                    ui.label("• When you save a value = default, it's REMOVED from storage");
                    ui.label("• This keeps settings.json minimal (only customizations)");
                    ui.label("• Validation happens in save_setting() - invalid values rejected");
                    ui.label("• Secret settings (.secret()) go to OS keychain, not JSON file");
                    ui.label("• Resetting a secret removes it from keychain too!");
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new(
                            "Check the 'Show JSON' checkbox to see what's actually stored!",
                        )
                        .weak(),
                    );
                });
            });
        });
    }
}

// UI Helper Methods
impl DemoApp {
    fn ui_status_status(&mut self, ui: &mut egui::Ui) {
        // Keychain status
        if self.keychain_enabled {
            ui.label(
                egui::RichText::new("🔐 Keychain: Enabled")
                    .color(egui::Color32::GREEN)
                    .small(),
            );
        } else {
            ui.label(
                egui::RichText::new("🔒 Keychain: Disabled (run with --features keychain)")
                    .color(egui::Color32::YELLOW)
                    .small(),
            );
        }

        ui.add_space(4.0);
        ui.label(
            egui::RichText::new(format!(
                "🗄️ Encrypted File: {}",
                self.encrypted_backend_status
            ))
            .small(),
        );

        ui.separator();

        // Status bar
        ui.horizontal(|ui| {
            ui.label(&self.ui.status_message);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("🔄 Reload").clicked() {
                    self.reload_settings();
                }
                ui.checkbox(&mut self.ui.show_json, "📄 Show JSON");
            });
        });
        ui.separator();
    }

    fn ui_app_settings(&mut self, ui: &mut egui::Ui) {
        ui.collapsing("📱 App Settings", |ui| {
            ui.horizontal(|ui| {
                ui.label("App Name:");
                let response = ui.text_edit_singleline(&mut self.settings.app_name);
                if response.lost_focus() {
                    self.save_setting("app", "name", &json!(self.settings.app_name));
                }
                if ui
                    .small_button("↩")
                    .on_hover_text("Reset to default")
                    .clicked()
                {
                    self.reset_setting("app", "name");
                }
            });
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                ui.label("Theme:");
                let old_theme = self.settings.theme.clone();
                egui::ComboBox::from_id_salt("theme")
                    .selected_text(match self.settings.theme.as_str() {
                        "light" => "☀️ Light",
                        "dark" => "🌙 Dark",
                        "auto" => "🔄 Auto",
                        _ => "Unknown",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.settings.theme,
                            "light".to_string(),
                            "☀️ Light",
                        );
                        ui.selectable_value(
                            &mut self.settings.theme,
                            "dark".to_string(),
                            "🌙 Dark",
                        );
                        ui.selectable_value(
                            &mut self.settings.theme,
                            "auto".to_string(),
                            "🔄 Auto",
                        );
                    });
                if self.settings.theme != old_theme {
                    self.save_setting("app", "theme", &json!(self.settings.theme));
                }
                if ui.small_button("↩").clicked() {
                    self.reset_setting("app", "theme");
                }
            });
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                ui.label("Font Size:");
                let old_size = self.settings.font_size;
                ui.add(egui::Slider::new(&mut self.settings.font_size, 8.0..=32.0).suffix("px"));
                if (self.settings.font_size - old_size).abs() > 0.1 {
                    self.save_setting("app", "font_size", &json!(self.settings.font_size));
                }
                if ui.small_button("↩").clicked() {
                    self.reset_setting("app", "font_size");
                }
            });
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                let old_anim = self.settings.animations;
                ui.checkbox(&mut self.settings.animations, "Enable Animations");
                if self.settings.animations != old_anim {
                    self.save_setting("app", "animations", &json!(self.settings.animations));
                }
                if ui.small_button("↩").clicked() {
                    self.reset_setting("app", "animations");
                }
            });
        });
    }

    fn ui_network_settings(&mut self, ui: &mut egui::Ui) {
        ui.collapsing("🌐 Network", |ui| {
            ui.horizontal(|ui| {
                ui.label("Timeout:");
                let old_timeout = self.settings.timeout;
                ui.add(egui::Slider::new(&mut self.settings.timeout, 5.0..=300.0).suffix(" sec"));
                if (self.settings.timeout - old_timeout).abs() > 0.1 {
                    self.save_setting("network", "timeout", &json!(self.settings.timeout));
                }
                if ui.small_button("↩").clicked() {
                    self.reset_setting("network", "timeout");
                }
            });
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                ui.label("Max Retries:");
                let old_retries = self.settings.retries;
                ui.add(egui::Slider::new(&mut self.settings.retries, 0.0..=10.0).step_by(1.0));
                if (self.settings.retries - old_retries).abs() > 0.1 {
                    self.save_setting("network", "retries", &json!(self.settings.retries));
                }
                if ui.small_button("↩").clicked() {
                    self.reset_setting("network", "retries");
                }
            });
        });
    }

    fn ui_user_settings(&mut self, ui: &mut egui::Ui) {
        ui.collapsing("👤 User (Validation Demo)", |ui| {
            ui.label("These fields have regex validation:");
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                ui.label("Email:");
                let response = ui.text_edit_singleline(&mut self.settings.email);
                if response.lost_focus() {
                    self.save_setting("user", "email", &json!(self.settings.email));
                }
                if ui.small_button("↩").clicked() {
                    self.reset_setting("user", "email");
                }
            });
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                ui.label("Username:");
                let response = ui.text_edit_singleline(&mut self.settings.username);
                if response.lost_focus() {
                    self.save_setting("user", "username", &json!(self.settings.username));
                }
                if ui.small_button("↩").clicked() {
                    self.reset_setting("user", "username");
                }
            });

            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("💡 Try invalid values to see validation errors!")
                    .small()
                    .weak(),
            );
        });
    }

    fn ui_secrets_settings(&mut self, ui: &mut egui::Ui) {
        ui.collapsing("🔐 Secrets (Keychain Demo)", |ui| {
            if self.keychain_enabled {
                ui.label(
                    egui::RichText::new(
                        "Secrets are stored in your OS keychain, NOT in settings.json!",
                    )
                    .color(egui::Color32::GREEN)
                    .small(),
                );
            } else {
                ui.label(
                    egui::RichText::new("⚠️ Run with --features keychain to enable secure storage")
                        .color(egui::Color32::YELLOW)
                        .small(),
                );
            }
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                ui.label("API Key:");
                if self.ui.show_api_key {
                    let response = ui.text_edit_singleline(&mut self.settings.api_key);
                    if response.lost_focus() {
                        self.save_setting("secrets", "api_key", &json!(self.settings.api_key));
                    }
                } else {
                    ui.label(if self.settings.api_key.is_empty() {
                        "(empty)"
                    } else {
                        "••••••••"
                    });
                }
                if ui
                    .small_button(if self.ui.show_api_key {
                        "👁"
                    } else {
                        "👁‍🗨"
                    })
                    .clicked()
                {
                    self.ui.show_api_key = !self.ui.show_api_key;
                }
                if ui.small_button("↩").clicked() {
                    self.reset_setting("secrets", "api_key");
                }
            });
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                ui.label("DB Password:");
                if self.ui.show_db_password {
                    let response = ui.text_edit_singleline(&mut self.settings.db_password);
                    if response.lost_focus() {
                        self.save_setting(
                            "secrets",
                            "db_password",
                            &json!(self.settings.db_password),
                        );
                    }
                } else {
                    ui.label(if self.settings.db_password.is_empty() {
                        "(empty)"
                    } else {
                        "••••••••"
                    });
                }
                if ui
                    .small_button(if self.ui.show_db_password {
                        "👁"
                    } else {
                        "👁‍🗨"
                    })
                    .clicked()
                {
                    self.ui.show_db_password = !self.ui.show_db_password;
                }
                if ui.small_button("↩").clicked() {
                    self.reset_setting("secrets", "db_password");
                }
            });

            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("💡 Check 'Show JSON' - secrets won't appear there!")
                    .small()
                    .weak(),
            );
        });
    }

    fn ui_advanced_settings(&mut self, ui: &mut egui::Ui) {
        ui.collapsing("⚙️ Advanced", |ui| {
            ui.horizontal(|ui| {
                let old_debug = self.settings.debug;
                ui.checkbox(&mut self.settings.debug, "Debug Mode");
                if self.settings.debug != old_debug {
                    self.save_setting("advanced", "debug", &json!(self.settings.debug));
                }
                if ui.small_button("↩").clicked() {
                    self.reset_setting("advanced", "debug");
                }
            });
        });
    }

    fn ui_remotes_settings(&mut self, ui: &mut egui::Ui) {
        ui.collapsing("📂 Sub-Settings (Per-Entity Config)", |ui| {
            ui.label(
                egui::RichText::new("Each 'remote' is stored as a separate JSON file")
                    .small()
                    .weak(),
            );
            ui.add_space(8.0);

            // Add new remote
            ui.group(|ui| {
                ui.label(egui::RichText::new("➕ Add Remote").strong());
                ui.add_space(4.0);

                ui.horizontal(|ui| {
                    ui.label("Name:");
                    ui.text_edit_singleline(&mut self.remotes.new_name);
                });

                ui.horizontal(|ui| {
                    ui.label("Type:");
                    egui::ComboBox::from_id_salt("remote_type")
                        .selected_text(&self.remotes.new_type)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.remotes.new_type,
                                "drive".to_string(),
                                "Google Drive",
                            );
                            ui.selectable_value(
                                &mut self.remotes.new_type,
                                "s3".to_string(),
                                "Amazon S3",
                            );
                            ui.selectable_value(
                                &mut self.remotes.new_type,
                                "dropbox".to_string(),
                                "Dropbox",
                            );
                            ui.selectable_value(
                                &mut self.remotes.new_type,
                                "onedrive".to_string(),
                                "OneDrive",
                            );
                        });
                });

                ui.add_space(4.0);
                if ui.button("➕ Add Remote").clicked() {
                    self.add_remote();
                }
            });

            ui.add_space(8.0);

            // List remotes
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("📋 Existing Remotes").strong());
                    if ui.small_button("🔄 Refresh").clicked() {
                        self.refresh_remotes();
                    }
                });
                ui.add_space(4.0);

                if self.remotes.list.is_empty() {
                    ui.label(egui::RichText::new("No remotes configured yet").weak());
                } else {
                    for remote in self.remotes.list.clone() {
                        ui.horizontal(|ui| {
                            let is_selected = self.remotes.selected.as_ref() == Some(&remote);
                            if ui.selectable_label(is_selected, &remote).clicked() {
                                self.remotes.selected = Some(remote.clone());
                                self.load_remote_data(&remote);
                            }
                            if ui.small_button("🗑️").on_hover_text("Delete").clicked() {
                                self.delete_remote(&remote);
                            }
                        });
                    }
                }
            });

            // Show selected remote data
            if let Some(ref selected) = self.remotes.selected.clone() {
                ui.add_space(8.0);
                ui.group(|ui| {
                    ui.label(egui::RichText::new(format!("📄 {selected}")).strong());
                    ui.add_space(4.0);
                    ui.add(
                        egui::TextEdit::multiline(&mut self.remotes.selected_data.clone())
                            .code_editor()
                            .desired_width(f32::INFINITY)
                            .desired_rows(4),
                    );
                });
            }

            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("💡 Files stored in ./example_config/remotes/")
                    .small()
                    .weak(),
            );
        });
    }

    fn ui_backup_settings(&mut self, ui: &mut egui::Ui) {
        ui.collapsing("💾 Backup & Restore", |ui| {
            ui.label(
                egui::RichText::new("Create and restore encrypted or plain backups")
                    .small()
                    .weak(),
            );
            ui.add_space(8.0);

            self.ui_backup_create(ui);
            ui.add_space(8.0);
            self.ui_backup_restore(ui);

            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("💡 Backups are stored in ./example_config/backups/")
                    .small()
                    .weak(),
            );
        });
    }

    fn ui_backup_create(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.label(egui::RichText::new("📦 Create Backup").strong());
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                ui.checkbox(&mut self.backup.use_encryption, "Encrypt backup");
                if self.backup.use_encryption {
                    ui.label("Password:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.backup.password)
                            .password(true)
                            .desired_width(120.0),
                    );
                }
            });

            ui.horizontal(|ui| {
                ui.label("Note (optional):");
                ui.text_edit_singleline(&mut self.backup.note);
            });

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("📦 Create Backup").clicked() {
                    self.create_backup();
                }
                if let Some(ref path) = self.backup.last_path {
                    ui.label(
                        egui::RichText::new(format!(
                            "Last: {:?}",
                            path.file_name().unwrap_or_default()
                        ))
                        .small()
                        .weak(),
                    );
                }
            });
        });
    }

    fn ui_backup_restore(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.label(egui::RichText::new("♻️ Restore Backup").strong());
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                if ui.button("🔄 Refresh List").clicked() {
                    self.backup.list = Self::scan_backups();
                    self.ui.status_message = format!("Found {} backups", self.backup.list.len());
                }
                ui.label(format!("{} backup(s) found", self.backup.list.len()));
            });

            if !self.backup.list.is_empty() {
                ui.add_space(4.0);
                let mut selection_changed = false;
                egui::ComboBox::from_label("")
                    .selected_text(
                        self.backup
                            .selected_index
                            .and_then(|i| {
                                self.backup.list.get(i).map(|p| {
                                    p.file_name()
                                        .unwrap_or_default()
                                        .to_string_lossy()
                                        .to_string()
                                })
                            })
                            .unwrap_or_else(|| "Select a backup...".to_string()),
                    )
                    .show_ui(ui, |ui| {
                        for (i, path) in self.backup.list.iter().enumerate() {
                            let name = path
                                .file_name()
                                .unwrap_or_default()
                                .to_string_lossy()
                                .to_string();
                            if ui
                                .selectable_value(&mut self.backup.selected_index, Some(i), &name)
                                .clicked()
                            {
                                selection_changed = true;
                            }
                        }
                    });

                // Analyze after loop to avoid borrow conflict
                if selection_changed {
                    self.analyze_backup();
                }
                if self.backup.restore_requires_password {
                    ui.horizontal(|ui| {
                        ui.label("🔒 Password:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.backup.restore_password)
                                .password(true)
                                .desired_width(120.0),
                        );
                    });
                }

                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if ui.button("🔍 Analyze").clicked() {
                        self.analyze_backup();
                    }
                    if ui.button("♻️ Restore Selected").clicked() {
                        self.restore_backup();
                    }
                });

                // Show analysis results
                if let Some(ref analysis) = self.backup.analysis {
                    ui.add_space(4.0);
                    ui.group(|ui| {
                        ui.label(egui::RichText::new(analysis).monospace().small());
                    });
                }
            }
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([550.0, 700.0])
            .with_min_inner_size([400.0, 400.0]),
        ..Default::default()
    };

    eframe::run_native(
        "rcman GUI Demo",
        options,
        Box::new(|cc| Ok(Box::new(DemoApp::new(cc)))),
    )
}
