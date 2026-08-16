use rcman_derive::SettingsSchema;
use serde::{Deserialize, Serialize};

#[derive(SettingsSchema, Default, Serialize, Deserialize)]
#[schema(category = "api")]
struct DuplicateAccessors {
    pub network_port: u16,

    #[setting(category = "api_network")]
    pub port: u16,
}

fn main() {}
