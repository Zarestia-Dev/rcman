use rcman_derive::SettingsSchema;
use serde::{Deserialize, Serialize};

#[derive(SettingsSchema, Default, Serialize, Deserialize)]
struct MissingCategorySettings {
    pub port: u16,
    pub host: String, // Will trigger a second missing category error!
}

fn main() {}
