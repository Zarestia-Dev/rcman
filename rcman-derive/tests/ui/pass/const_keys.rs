use rcman_derive::SettingsSchema;
use serde::{Deserialize, Serialize};

#[derive(SettingsSchema, Default, Serialize, Deserialize)]
#[schema(category = "network")]
struct ServerSettings {
    #[setting(rename = "custom_port")]
    pub port: u16,

    pub host: String,
}

fn main() {
    assert_eq!(ServerSettings::PORT, "network.custom_port");
    assert_eq!(ServerSettings::HOST, "network.host");
    assert_eq!(
        ServerSettings::ALL_KEYS,
        &[ServerSettings::PORT, ServerSettings::HOST]
    );
}
