use rcman_derive::SettingsSchema;
use serde::{Deserialize, Serialize};

#[derive(SettingsSchema, Default, Serialize, Deserialize)]
#[schema(category = 123)]
struct BadCategoryType {
    port: u16,
}

#[derive(SettingsSchema, Default, Serialize, Deserialize)]
#[schema(category = "test")]
struct BadNumericLiteral {
    #[setting(min = "ten")]
    port: u16,

    #[setting(max = true)]
    port2: u16,
}

fn main() {}
