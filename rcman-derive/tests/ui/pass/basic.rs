use rcman::SettingsSchema;
use rcman_derive::SettingsSchema;
use serde::{Deserialize, Serialize};

#[derive(SettingsSchema, Default, Serialize, Deserialize)]
#[schema(category = "test_cat")]
struct BasicSettings {
    #[setting(min = 1, max = 100)]
    pub port: u16,

    #[setting(pattern = "^[a-z]+$")]
    pub name: String,

    pub enabled: bool,
}

fn main() {
    let _map = BasicSettings::get_metadata();
}
