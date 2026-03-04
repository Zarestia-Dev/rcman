use rcman::SettingsSchema as _;
use rcman_derive::SettingsSchema;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(SettingsSchema, Default, Serialize, Deserialize)]
#[schema(category = "test")]
struct PathSettings {
    pub log_dir: PathBuf,
}

fn main() {}
