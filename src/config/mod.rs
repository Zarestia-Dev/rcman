//! Core configuration types and traits
//!
//! This module contains the foundational types for settings management:
//! - `SettingsConfig` - Configuration for the settings manager
//! - `SettingsSchema` - Trait for defining settings with metadata
//! - `SettingMetadata` - Rich metadata for settings (type, description, constraints)

mod schema;
mod types;

pub use schema::{
    NumberConstraints, SettingConstraints, SettingMetadata, SettingOption, SettingType,
    SettingsSchema, TextConstraints, meta, opt,
};

pub use types::{DefaultEnvSource, EnvSource, SettingsConfig, SettingsConfigBuilder};
