use rcman::SettingsSchema;
use rcman_derive::SettingsSchema;
use serde::{Deserialize, Serialize};

#[derive(SettingsSchema, Default, Serialize, Deserialize)]
#[schema(category = "network")]
struct ServerConfig {
    #[setting(min = 1024, max = 65535)]
    pub port: u16,

    #[setting(pattern = "^https?://")]
    pub url: String,

    #[setting(options(("debug", "Debug"), ("info", "Info"), ("warn", "Warn")))]
    pub log_level: String,

    #[setting(min = 1, max = 10)]
    pub retry_count: Option<u8>,
}

#[derive(SettingsSchema, Default, Serialize, Deserialize)]
#[schema(category = "app")]
struct AppConfig {
    pub server: ServerConfig,

    #[setting(min = 0, max = 100)]
    pub opacity: u8,
}

#[derive(SettingsSchema, Serialize, Deserialize)]
#[serde(tag = "type")]
enum ActionConfig {
    #[serde(rename = "server")]
    Server(ServerConfig),
    #[serde(rename = "app")]
    App(AppConfig),
}

impl Default for ActionConfig {
    fn default() -> Self {
        Self::Server(ServerConfig::default())
    }
}

fn main() {
    let mut server = ServerConfig::default();
    server.port = 8080;
    server.url = "https://example.com".to_string();
    server.log_level = "info".to_string();

    // Inherent validate method callable without trait in scope:
    assert!(server.validate().is_ok());

    // Trait validate method via SettingsSchema trait:
    assert!(<ServerConfig as SettingsSchema>::validate(&server).is_ok());

    let mut app = AppConfig::default();
    app.server = server;
    app.opacity = 50;

    assert!(app.validate().is_ok());

    let action = ActionConfig::App(app);
    assert!(action.validate().is_ok());
}
