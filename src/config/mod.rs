//! Core configuration types and traits
//!
//! This module contains the foundational types for settings management:
//! - `SettingsConfig` - Configuration for the settings manager
//! - `SettingsSchema` - Trait for defining settings with metadata
//! - `SettingMetadata` - Rich metadata for settings (type, description, constraints)

mod schema;
mod types;

pub use schema::{
    SettingFlags, SettingMetadata, SettingOption, SettingSystemFlags, SettingType, SettingUiFlags,
    SettingsSchema, opt,
};

pub use types::{DefaultEnvSource, EnvSource, SettingsConfig, SettingsConfigBuilder};
