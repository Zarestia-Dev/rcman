// Derive macro usage example for rcman
//
// Run with: cargo run --example derive_usage --features derive

use rcman::{DeriveSettingsSchema, SettingsManager};
use serde::{Deserialize, Serialize};
use serde_json::json;

// =============================================================================
// Settings defined using the derive macro
// =============================================================================

/// General application settings
#[derive(Debug, Clone, Serialize, Deserialize, DeriveSettingsSchema)]
#[schema(category = "general")]
pub struct GeneralSettings {
    #[setting(label = "Enable Tray Icon", description = "Show icon in system tray")]
    pub tray_enabled: bool,

    #[setting(label = "Start on Startup", description = "Launch app on system boot")]
    pub start_on_startup: bool,

    #[setting(label = "Notifications", description = "Show desktop notifications")]
    pub notifications: bool,
}

impl Default for GeneralSettings {
    fn default() -> Self {
        Self {
            tray_enabled: true,
            start_on_startup: false,
            notifications: true,
        }
    }
}

/// UI/Appearance settings
#[derive(Debug, Clone, Serialize, Deserialize, DeriveSettingsSchema)]
#[schema(category = "ui")]
pub struct UiSettings {
    #[setting(
        label = "Theme",
        options(("light", "Light"), ("dark", "Dark"), ("system", "System"))
    )]
    pub theme: String,

    #[setting(
        label = "Font Size",
        description = "UI font size in pixels",
        min = 8,
        max = 32
    )]
    pub font_size: u8,
}

impl Default for UiSettings {
    fn default() -> Self {
        Self {
            theme: "system".to_string(),
            font_size: 14,
        }
    }
}

/// Network settings with advanced options
#[derive(Debug, Clone, Serialize, Deserialize, DeriveSettingsSchema)]
#[schema(category = "network")]
pub struct NetworkSettings {
    #[setting(
        label = "API Port",
        description = "Port for API server",
        min = 1024,
        max = 65535
    )]
    pub port: u16,

    #[setting(label = "Enable Proxy", advanced)]
    pub proxy_enabled: bool,

    #[setting(label = "Proxy URL", description = "HTTP proxy URL", advanced)]
    pub proxy_url: String,

    #[setting(
        label = "Allowed IPs",
        description = "List of IP addresses allowed to connect"
    )]
    pub allowed_ips: Vec<String>,
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            port: 8080,
            proxy_enabled: false,
            proxy_url: String::new(),
            allowed_ips: vec!["127.0.0.1".to_string(), "::1".to_string()],
        }
    }
}

/// Complete app settings using nested structs
#[derive(Debug, Clone, Default, Serialize, Deserialize, DeriveSettingsSchema)]
pub struct AppSettings {
    pub general: GeneralSettings,
    pub ui: UiSettings,
    pub network: NetworkSettings,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("📦 rcman Derive Macro Example\n");

    // Initialize settings manager
    let manager = SettingsManager::builder("derive-example", "1.0.0")
        .config_dir("./example_config")
        .build()?;

    // Load settings - derive macro generates the schema automatically
    let settings = manager.load_settings::<AppSettings>()?;

    println!("✅ Loaded {} settings:", settings.len());
    for (key, meta) in &settings {
        println!("  {} = {:?} (default: {:?})", key, meta.value, meta.default);
    }

    // Save a setting
    println!("\n🔧 Changing theme to 'dark'...");
    manager.save_setting::<AppSettings>("ui", "theme", json!("dark"))?;

    // Load startup settings as struct
    let app: AppSettings = manager.settings()?;
    println!("✅ Theme is now: {}", app.ui.theme);

    // Reset to default
    println!("\n🔄 Resetting theme...");
    manager.reset_setting::<AppSettings>("ui", "theme")?;

    let app: AppSettings = manager.settings()?;
    println!("✅ Theme reset to: {}", app.ui.theme);

    // Working with list settings
    println!("\n📋 List Settings Example:");
    println!("Current allowed IPs: {:?}", app.network.allowed_ips);

    println!("\n🔧 Adding new IP to allowed list...");
    let mut new_ips = app.network.allowed_ips.clone();
    new_ips.push("192.168.1.1".to_string());
    manager.save_setting::<AppSettings>("network", "allowed_ips", json!(new_ips))?;

    let app: AppSettings = manager.settings()?;
    println!("✅ Updated allowed IPs: {:?}", app.network.allowed_ips);

    println!(
        "\n💾 Config location: {:?}",
        manager.config().settings_path()
    );

    Ok(())
}
