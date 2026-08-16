use rcman_derive::SettingsSchema;
use serde::{Deserialize, Serialize};

#[derive(SettingsSchema, Default, Serialize, Deserialize)]
#[schema(category = "test")]
struct EmptySettings {}

#[derive(SettingsSchema, Default, Serialize, Deserialize)]
#[schema(category = "test")]
struct TupleSettings(u16, String);

#[derive(SettingsSchema)]
union UnionSettings {
    a: u32,
}

fn main() {}
