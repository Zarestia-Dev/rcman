use rcman_derive::SettingsSchema;
use serde::{Deserialize, Serialize};

#[derive(SettingsSchema, Serialize, Deserialize)]
#[serde(tag = "type")]
enum UnitVariantEnum {
    Unit,
}

#[derive(SettingsSchema, Serialize, Deserialize)]
#[serde(tag = "type")]
enum MultiTupleEnum {
    Multi(u32, String),
}

fn main() {}
