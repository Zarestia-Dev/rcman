//! Restore functionality

use super::archive::{extract_zip_archive, read_file_from_zip};
use super::types::*;
use crate::error::{Error, Result};
use crate::storage::StorageBackend;
#[cfg(feature = "profiles")]
use crate::profiles::{MANIFEST_FILE, PROFILES_DIR};
use log::{debug, info, warn};
use std::fs;
use std::path::Path;

impl<'a, S: StorageBackend + 'static> super::BackupManager<'a, S> {
    /// Restore from a backup
    pub fn restore(&self, options: RestoreOptions) -> Result<RestoreResult> {
        let mode_str = if options.dry_run { "[DRY RUN] " } else { "" };
        info!(
            "{}📦 Restoring from backup: {:?}",
            mode_str, options.backup_path
        );

        // Analyze the backup first
        let analysis = self.analyze(&options.backup_path)?;

        // Check manifest version compatibility
        if !analysis.is_valid {
            return Err(Error::InvalidBackup(format!(
                "Backup manifest version {} is not supported (supported: {}-{})",
                analysis.manifest.version,
                super::types::MANIFEST_VERSION_MIN_SUPPORTED,
                super::types::MANIFEST_VERSION_MAX_SUPPORTED
            )));
        }

        // Check password requirement
        if analysis.requires_password && options.password.is_none() {
            return Err(Error::PasswordRequired);
        }

        // Create temp directory for extraction
        let temp_dir = tempfile::tempdir().map_err(|e| Error::RestoreFailed(e.to_string()))?;
        let extract_dir = temp_dir.path().join("extracted");

        // Extract the inner data archive
        let data_filename = "data.zip";
        let data_bytes = read_file_from_zip(&options.backup_path, data_filename)?;

        let data_archive_path = temp_dir.path().join(data_filename);
        fs::write(&data_archive_path, &data_bytes).map_err(|e| Error::FileWrite {
            path: data_archive_path.display().to_string(),
            source: e,
        })?;

        // Verify checksum if requested and available
        let mut result = RestoreResult {
            is_dry_run: options.dry_run,
            ..Default::default()
        };

        if options.verify_checksum {
            if let Some(ref expected_checksum) = analysis.manifest.integrity.sha256 {
                let (actual_checksum, _) = super::archive::calculate_file_hash(&data_archive_path)?;
                let is_valid = &actual_checksum == expected_checksum;
                result.checksum_valid = Some(is_valid);

                if !is_valid {
                    warn!(
                        "⚠️ Checksum mismatch! Expected: {}, Got: {}",
                        expected_checksum, actual_checksum
                    );
                    return Err(Error::InvalidBackup(
                        "Data archive checksum verification failed - backup may be corrupted"
                            .into(),
                    ));
                }
                debug!("✅ Checksum verified: {}", actual_checksum);
            } else {
                debug!("ℹ️ No checksum in manifest, skipping verification");
            }
        }

        // Extract data archive (always zip now)
        extract_zip_archive(
            &data_archive_path,
            &extract_dir,
            options.password.as_deref(),
        )?;

        // 1. Restore main settings
        if options.restore_settings {
            #[cfg_attr(not(feature = "profiles"), allow(unused_variables))]
            let config = self.manager.config();
            
            #[cfg(feature = "profiles")]
            let profiles_enabled = config.profiles_enabled;
            #[cfg(not(feature = "profiles"))]
            let profiles_enabled = false;

            if profiles_enabled {
                #[cfg(feature = "profiles")]
                {
                    // Restore .profiles.json
                    let profiles_manifest = extract_dir.join(MANIFEST_FILE);
                    let target_manifest = config.config_dir.join(MANIFEST_FILE);
                    
                    if profiles_manifest.exists() {
                        if target_manifest.exists() && !options.overwrite_existing {
                             result.skipped.push(MANIFEST_FILE.into());
                             warn!("{}⚠️ Skipping {} (exists)", mode_str, MANIFEST_FILE);
                        } else if options.dry_run {
                             result.restored.push(MANIFEST_FILE.into());
                             debug!("{}📋 Would restore {}", mode_str, MANIFEST_FILE);
                        } else {
                             fs::copy(&profiles_manifest, &target_manifest).map_err(|e| Error::FileWrite {
                                 path: target_manifest.display().to_string(),
                                 source: e,
                             })?;
                             result.restored.push(MANIFEST_FILE.into());
                        }
                    }

                    // Restore profiles
                    let profiles_src_dir = extract_dir.join(PROFILES_DIR);
                    if profiles_src_dir.exists() {
                        let target_profiles_dir = config.config_dir.join(PROFILES_DIR);
                        
                        // Handle single profile restore request
                        let profiles_to_restore = if let Some(ref profile) = options.restore_profile {
                             vec![profile.clone()]
                        } else {
                             // Restore all found in source
                             fs::read_dir(&profiles_src_dir)
                                 .ok() 
                                 .map(|entries| {
                                     entries.filter_map(|e| e.ok())
                                        .map(|e| e.file_name().to_string_lossy().to_string())
                                        .collect()
                                 })
                                 .unwrap_or_default()
                        };

                        for profile_name in profiles_to_restore {
                             let src_profile_path = profiles_src_dir.join(&profile_name);
                             if !src_profile_path.exists() {
                                 warn!("⚠️ Profile '{}' not found in backup", profile_name);
                                 continue;
                             }

                             // Determine target profile name (rename if requested)
                             let target_profile_name = if options.restore_profile.is_some() {
                                 options.restore_profile_as.as_ref().unwrap_or(&profile_name).clone()
                             } else {
                                 profile_name.clone()
                             };

                             let target_profile_path = target_profiles_dir.join(&target_profile_name);
                             fs::create_dir_all(&target_profile_path).map_err(|e| Error::DirectoryCreate {
                                 path: target_profile_path.display().to_string(),
                                 source: e,
                             })?;

                             let src_settings = src_profile_path.join("settings.json");
                             if src_settings.exists() {
                                 let dest_settings = target_profile_path.join("settings.json");
                                 if dest_settings.exists() && !options.overwrite_existing {
                                     result.skipped.push(format!("profiles/{}/settings.json", target_profile_name));
                                 } else if options.dry_run {
                                     result.restored.push(format!("profiles/{}/settings.json", target_profile_name));
                                     debug!("{}📋 Would restore settings for profile {}", mode_str, target_profile_name);
                                 } else {
                                     fs::copy(&src_settings, &dest_settings).map_err(|e| Error::FileWrite {
                                         path: dest_settings.display().to_string(),
                                         source: e,
                                     })?;
                                     result.restored.push(format!("profiles/{}/settings.json", target_profile_name));
                                     debug!("✅ Restored settings for profile {}", target_profile_name);
                                 }
                             }
                        }
                    }
                }
            } else {
                // Legacy behavior
                if analysis.manifest.contents.settings {
                    let settings_src = extract_dir.join("settings.json");
                    if settings_src.exists() {
                        let settings_dest = self.manager.config().settings_path();

                        if settings_dest.exists() && !options.overwrite_existing {
                            result.skipped.push("settings.json".into());
                            warn!(
                                "{}⚠️ Skipping settings.json (exists, overwrite disabled)",
                                mode_str
                            );
                        } else if options.dry_run {
                            result.restored.push("settings.json".into());
                            debug!("{}📋 Would restore settings.json", mode_str);
                        } else {
                            fs::copy(&settings_src, &settings_dest).map_err(|e| Error::FileWrite {
                                path: settings_dest.display().to_string(),
                                source: e,
                            })?;
                            result.restored.push("settings.json".into());
                            debug!("✅ Restored settings.json");
                        }
                    }
                }
            }
        }

        // 2. Restore sub-settings
        let sub_settings_to_restore = if options.restore_sub_settings.is_empty() {
            // Convert manifest entries to basic HashMap for processing
            analysis.manifest.contents.sub_settings_list()
        } else {
            options.restore_sub_settings.clone()
        };

        for (sub_type, items_filter) in sub_settings_to_restore {
            let sub_src_dir = extract_dir.join(&sub_type);
            
            // Get sub-settings handler
            let sub = match self.manager.sub_settings(&sub_type) {
                Ok(s) => s,
                Err(_) => {
                    warn!(
                        "⚠️ Sub-settings type '{}' not registered, skipping",
                        sub_type
                    );
                    continue;
                }
            };
            
            // Check if we are dealing with a profiled backup for this entry
            #[cfg_attr(not(feature = "profiles"), allow(unused_variables))]
            let manifest_entry = analysis.manifest.contents.sub_settings.get(&sub_type);
            
            #[cfg(feature = "profiles")]
            let is_profiled_backup = matches!(manifest_entry, Some(SubSettingsManifestEntry::Profiled { .. }));
            #[cfg(not(feature = "profiles"))]
            let is_profiled_backup = false;
            
            #[cfg(feature = "profiles")]
            let target_profiles_enabled = sub.profiles_enabled();
            #[cfg(not(feature = "profiles"))]
            let _target_profiles_enabled = false;

            if is_profiled_backup {
                #[cfg(feature = "profiles")]
                {
                    // Restore .profiles.json if target supports it
                    if target_profiles_enabled {
                         let profiles_manifest = sub_src_dir.join(MANIFEST_FILE);
                         let target_root = sub.root_path();
                         let target_manifest = target_root.join(MANIFEST_FILE);

                         if profiles_manifest.exists() {
                             if target_manifest.exists() && !options.overwrite_existing {
                                 // Skip
                             } else if !options.dry_run {
                                 fs::create_dir_all(&target_root).ok();
                                 fs::copy(&profiles_manifest, &target_manifest).ok();
                             }
                         }

                         // Iterate profiles
                         let profiles_src_dir = sub_src_dir.join(PROFILES_DIR);
                         let target_profiles_dir = target_root.join(PROFILES_DIR);
                         
                         if profiles_src_dir.exists() {
                             let profiles_to_restore = if let Some(ref profile) = options.restore_profile {
                                 vec![profile.clone()]
                             } else {
                                fs::read_dir(&profiles_src_dir)
                                     .ok()
                                     .map(|entries| {
                                         entries.filter_map(|e| e.ok())
                                            .map(|e| e.file_name().to_string_lossy().to_string())
                                            .collect()
                                     })
                                     .unwrap_or_default()
                             };

                             for profile_name in profiles_to_restore {
                                 let src_profile_path = profiles_src_dir.join(&profile_name);
                                 if !src_profile_path.exists() { continue; }

                                 let target_profile_name = if options.restore_profile.is_some() {
                                     options.restore_profile_as.as_ref().unwrap_or(&profile_name).clone()
                                 } else {
                                     profile_name.clone()
                                 };

                                 let target_profile_dir = target_profiles_dir.join(&target_profile_name);
                                 
                                 // Restore content of profile (SingleFile or MultiFile)
                                 // We scan src_profile_path for .json files
                                 if let Ok(entries) = fs::read_dir(&src_profile_path) {
                                     for entry in entries.filter_map(|e| e.ok()) {
                                         let path = entry.path();
                                         if path.extension().and_then(|s| s.to_str()) == Some("json") {
                                             let file_name = entry.file_name();
                                             let stem = path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
                                             
                                             // Filter items
                                             if !items_filter.is_empty() && !items_filter.contains(&stem) {
                                                 continue;
                                             }

                                             // Target file
                                             let dest = target_profile_dir.join(&file_name);
                                             
                                             if dest.exists() && !options.overwrite_existing {
                                                 result.skipped.push(format!("{}/{}/{}", sub_type, target_profile_name, stem));
                                             } else if options.dry_run {
                                                 result.restored.push(format!("{}/{}/{}", sub_type, target_profile_name, stem));
                                                 debug!("{}📋 Would restore {} to profile {}", mode_str, stem, target_profile_name);                                                 
                                             } else {
                                                 fs::create_dir_all(&target_profile_dir).map_err(|e| Error::DirectoryCreate {
                                                      path: target_profile_dir.display().to_string(),
                                                      source: e
                                                 })?;
                                                 
                                                 fs::copy(&path, &dest).map_err(|e| Error::FileWrite {
                                                      path: dest.display().to_string(),
                                                      source: e
                                                 })?;
                                                 result.restored.push(format!("{}/{}/{}", sub_type, target_profile_name, stem));
                                                 debug!("✅ Restored {} to profile {}", stem, target_profile_name);
                                             }
                                         }
                                     }
                                 }
                             }
                         }
                    } else {
                        // Profiled backup -> Flat target?
                        // If specific profile requested, we can flatten it to root.
                        if let Some(ref src_profile) = options.restore_profile {
                             let profiles_src_dir = sub_src_dir.join(PROFILES_DIR);
                             let src_profile_path = profiles_src_dir.join(src_profile);
                             
                             if src_profile_path.exists() {
                                 // Restore items from this profile to active flat root
                                 // We can use 'sub.set' here effectively as we are targeting the active flat config
                                 // But we need to load json first.
                                 
                                 if let Ok(entries) = fs::read_dir(&src_profile_path) {
                                     for entry in entries.filter_map(|e| e.ok()) {
                                          let path = entry.path();
                                          if path.extension().and_then(|s| s.to_str()) == Some("json") {
                                               let stem = path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
                                               if !items_filter.is_empty() && !items_filter.contains(&stem) { continue; }
                                               
                                               let content = fs::read_to_string(&path).map_err(|e| Error::FileRead {
                                                   path: path.display().to_string(),
                                                   source: e
                                               })?;
                                               let value: serde_json::Value = serde_json::from_str(&content)?;
                                               
                                               if sub.exists(&stem)? && !options.overwrite_existing {
                                                   result.skipped.push(format!("{}/{}", sub_type, stem));
                                               } else if options.dry_run {
                                                   result.restored.push(format!("{}/{}", sub_type, stem));
                                               } else {
                                                   sub.set(&stem, &value)?;
                                                   result.restored.push(format!("{}/{}", sub_type, stem));
                                               }
                                          }
                                     }
                                 }
                             }
                        } else {
                             warn!("⚠️ Cannot restore profiled backup of '{}' to non-profiled target without specifying --restore-profile", sub_type);
                        }
                    }
                }
            } else {
                // Not profiled backup, or profiles not compiled in.
                // Standard flat restore logic (existing code adapted)
                let sub_single_file_src = extract_dir.join(format!("{}.json", sub_type));

                // ... [Existing Logic] ...
                // To minimize diff complexity, I'll inline the existing logic here for the flat case
                
                 // Collect entries to restore from either directory or single file
            let mut entries_to_restore: Vec<(String, serde_json::Value)> = Vec::new();

            if sub_single_file_src.exists() {
                // Restore from single file
                let content =
                    fs::read_to_string(&sub_single_file_src).map_err(|e| Error::FileRead {
                        path: sub_single_file_src.display().to_string(),
                        source: e,
                    })?;

                let file_data: serde_json::Value =
                    serde_json::from_str(&content).map_err(|e| Error::Parse(e.to_string()))?;

                if let Some(obj) = file_data.as_object() {
                    for (key, value) in obj {
                        entries_to_restore.push((key.clone(), value.clone()));
                    }
                }
            } else if sub_src_dir.exists() {
                // Restore from directory
                for entry in fs::read_dir(&sub_src_dir).map_err(|e| Error::FileRead {
                    path: sub_src_dir.display().to_string(),
                    source: e,
                })? {
                    let entry = entry.map_err(|e| Error::FileRead {
                        path: sub_src_dir.display().to_string(),
                        source: e,
                    })?;

                    let file_name = entry.file_name();
                    let name_str = file_name.to_string_lossy();

                    if !name_str.ends_with(".json") {
                        continue;
                    }

                    let entry_name = name_str.trim_end_matches(".json").to_string();

                    let content =
                        fs::read_to_string(entry.path()).map_err(|e| Error::FileRead {
                            path: entry.path().display().to_string(),
                            source: e,
                        })?;

                    let value: serde_json::Value = serde_json::from_str(&content)?;
                    entries_to_restore.push((entry_name, value));
                }
            }

            // Process the collected entries
            for (entry_name, value) in entries_to_restore {
                // Filter by items if specified
                if !items_filter.is_empty() && !items_filter.contains(&entry_name) {
                    continue;
                }

                let entry_id = format!("{}/{}", sub_type, entry_name);

                // Check if exists
                if !options.overwrite_existing && sub.exists(&entry_name)? {
                    result.skipped.push(entry_id);
                    continue;
                }

                if options.dry_run {
                    result.restored.push(entry_id.clone());
                    debug!("{}📋 Would restore {}", mode_str, entry_id);
                    continue;
                }

                sub.set(&entry_name, &value)?;

                result.restored.push(entry_id.clone());
                debug!("✅ Restored {}", entry_id);
            }
            }
        }

        // 3. Restore external configs (if any requested)
        if !options.restore_external_configs.is_empty() || options.restore_sub_settings.is_empty() {
            let external_dir = extract_dir.join("external");
            if external_dir.exists() {
                for config_name in &analysis.manifest.contents.external_configs {
                    // Skip if specific configs requested and this isn't one
                    if !options.restore_external_configs.is_empty()
                        && !options.restore_external_configs.contains(config_name)
                    {
                        continue;
                    }

                    match self.resolve_external_config(config_name) {
                        Some(external_config) => {
                            // Read data from backup
                            let src = external_dir.join(&external_config.archive_filename);
                            let data = fs::read(&src).map_err(|e| Error::FileRead {
                                path: src.display().to_string(),
                                source: e,
                            })?;

                            // Handle different import targets
                            match &external_config.import_target {
                                super::types::ImportTarget::ReadOnly => {
                                    debug!(
                                        "⏭️ Skipping read-only external config: {}",
                                        config_name
                                    );
                                    result.skipped.push(config_name.clone());
                                    continue;
                                }
                                super::types::ImportTarget::File(dest_path) => {
                                    if dest_path.exists() && !options.overwrite_existing {
                                        result.skipped.push(config_name.clone());
                                        debug!(
                                            "{}⚠️ Skipping external {} (exists)",
                                            mode_str, config_name
                                        );
                                    } else if options.dry_run {
                                        result.restored.push(config_name.clone());
                                        debug!(
                                            "{}📋 Would restore external {}",
                                            mode_str, config_name
                                        );
                                    } else {
                                        if let Some(parent) = dest_path.parent() {
                                            fs::create_dir_all(parent).map_err(|e| {
                                                Error::FileWrite {
                                                    path: parent.display().to_string(),
                                                    source: e,
                                                }
                                            })?;
                                        }
                                        fs::write(dest_path, &data).map_err(|e| {
                                            Error::FileWrite {
                                                path: dest_path.display().to_string(),
                                                source: e,
                                            }
                                        })?;
                                        result.restored.push(config_name.clone());
                                        debug!("✅ Restored external {}", config_name);
                                    }
                                }
                                super::types::ImportTarget::Command { program, args } => {
                                    if options.dry_run {
                                        result.restored.push(config_name.clone());
                                        debug!("{}📋 Would pipe to command: {}", mode_str, program);
                                    } else {
                                        use std::io::Write;
                                        use std::process::{Command, Stdio};

                                        let mut child = Command::new(program)
                                            .args(args)
                                            .stdin(Stdio::piped())
                                            .spawn()
                                            .map_err(|e| {
                                                Error::BackupFailed(format!(
                                                    "Failed to spawn command '{}': {}",
                                                    program, e
                                                ))
                                            })?;

                                        if let Some(mut stdin) = child.stdin.take() {
                                            stdin.write_all(&data).map_err(|e| {
                                                Error::BackupFailed(format!(
                                                    "Failed to write to command stdin: {}",
                                                    e
                                                ))
                                            })?;
                                        }

                                        let status = child.wait().map_err(|e| {
                                            Error::BackupFailed(format!(
                                                "Command '{}' failed: {}",
                                                program, e
                                            ))
                                        })?;

                                        if !status.success() {
                                            return Err(Error::BackupFailed(format!(
                                                "Command '{}' exited with code {:?}",
                                                program,
                                                status.code()
                                            )));
                                        }

                                        result.restored.push(config_name.clone());
                                        debug!("✅ Restored external {} via command", config_name);
                                    }
                                }
                                super::types::ImportTarget::Handler(handler) => {
                                    if options.dry_run {
                                        result.restored.push(config_name.clone());
                                        debug!(
                                            "{}📋 Would call custom handler for {}",
                                            mode_str, config_name
                                        );
                                    } else {
                                        handler(&data)?;
                                        result.restored.push(config_name.clone());
                                        debug!("✅ Restored external {} via handler", config_name);
                                    }
                                }
                            }
                        }
                        None => {
                            result.external_pending.push(config_name.clone());
                            warn!(
                                "⚠️ Unknown external config ID: {}, requires manual restore",
                                config_name
                            );
                        }
                    }
                }
            }
        }

        info!(
            "✅ Restore complete: {} restored, {} skipped",
            result.restored.len(),
            result.skipped.len()
        );

        Ok(result)
    }

    /// Get the path to an external config from a backup (for manual restoration)
    pub fn get_external_config_from_backup(
        &self,
        backup_path: &Path,
        config_name: &str,
        password: Option<&str>,
    ) -> Result<Vec<u8>> {
        let _analysis = self.analyze(backup_path)?;
        let data_filename = "data.zip";

        // Extract the data archive temporarily
        let temp_dir = tempfile::tempdir().map_err(|e| Error::RestoreFailed(e.to_string()))?;
        let data_bytes = read_file_from_zip(backup_path, data_filename)?;
        let data_archive_path = temp_dir.path().join(data_filename);
        fs::write(&data_archive_path, data_bytes).map_err(|e| Error::FileWrite {
            path: data_archive_path.display().to_string(),
            source: e,
        })?;

        let extract_dir = temp_dir.path().join("extracted");

        // Extract (always zip now)
        extract_zip_archive(&data_archive_path, &extract_dir, password)?;

        let config_path = extract_dir.join("external").join(config_name);
        fs::read(&config_path).map_err(|e| Error::FileRead {
            path: config_path.display().to_string(),
            source: e,
        })
    }

    /// Helper to resolve external config from ID using registered providers
    fn resolve_external_config(&self, id: &str) -> Option<super::types::ExternalConfig> {
        // Check static configs in settings first
        if let Some(cfg) = self
            .manager
            .config()
            .external_configs
            .iter()
            .find(|c| c.id == id)
        {
            return Some(cfg.clone());
        }

        // Check dynamic providers
        if let Ok(providers) = self.manager.external_providers.read() {
            for provider in providers.iter() {
                for cfg in provider.get_configs() {
                    if cfg.id == id {
                        return Some(cfg);
                    }
                }
            }
        }

        None
    }
}

/// Result of a restore operation
#[derive(Debug, Default)]
pub struct RestoreResult {
    /// Items that were restored
    pub restored: Vec<String>,

    /// Items that were skipped (already exist)
    pub skipped: Vec<String>,

    /// External configs that need manual handling
    pub external_pending: Vec<String>,

    /// Whether this was a dry run (no actual changes made)
    pub is_dry_run: bool,

    /// Whether the checksum was verified successfully
    pub checksum_valid: Option<bool>,
}

impl RestoreResult {
    /// Check if anything was restored
    pub fn has_changes(&self) -> bool {
        !self.restored.is_empty()
    }

    /// Get total item count
    pub fn total(&self) -> usize {
        self.restored.len() + self.skipped.len()
    }

    /// Would this restore have made changes (for dry run results)
    pub fn would_change(&self) -> bool {
        !self.restored.is_empty() || self.checksum_valid == Some(false)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SettingsConfig;
    use crate::manager::SettingsManager;
    use crate::storage::JsonStorage;
    use crate::sub_settings::SubSettingsConfig;
    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn test_backup_and_restore_roundtrip() {
        let temp = tempdir().unwrap();

        // Setup manager with settings and sub-settings
        let config = SettingsConfig {
            config_dir: temp.path().join("config"),
            settings_file: "settings.json".into(),
            app_name: "test".into(),
            app_version: "1.0.0".into(),
            storage: JsonStorage::new(),
            enable_credentials: false,
            external_configs: Vec::new(),
            env_prefix: None,
            env_overrides_secrets: false,
            migrator: None, #[cfg(feature = "profiles")] profiles_enabled: false,
            #[cfg(feature = "profiles")]
            profile_migrator: crate::profiles::ProfileMigrator::None,
        };

        fs::create_dir_all(&config.config_dir).unwrap();
        fs::write(
            config.config_dir.join("settings.json"),
            r#"{"test": {"value": 42}}"#,
        )
        .unwrap();

        let manager = SettingsManager::new(config).unwrap();
        manager.register_sub_settings(SubSettingsConfig::new("items"));

        let items = manager.sub_settings("items").unwrap();
        items.set("item1", &json!({"name": "First"})).unwrap();

        // Create backup
        let backup = manager.backup();
        let backup_path = backup
            .create(BackupOptions {
                output_dir: temp.path().join("backups"),
                include_sub_settings: vec!["items".into()],
                ..Default::default()
            })
            .unwrap();

        // Setup fresh manager (simulating a new installation)
        let temp2 = tempdir().unwrap();
        let config2 = SettingsConfig {
            config_dir: temp2.path().to_path_buf(),
            settings_file: "settings.json".into(),
            app_name: "test".into(),
            app_version: "1.0.0".into(),
            storage: JsonStorage::new(),
            enable_credentials: false,
            external_configs: Vec::new(),
            env_prefix: None,
            env_overrides_secrets: false,
            migrator: None, #[cfg(feature = "profiles")] profiles_enabled: false,
            #[cfg(feature = "profiles")]
            profile_migrator: crate::profiles::ProfileMigrator::None,
        };

        let manager2 = SettingsManager::new(config2).unwrap();
        manager2.register_sub_settings(SubSettingsConfig::new("items"));

        // Restore
        let result = manager2
            .backup()
            .restore(RestoreOptions {
                backup_path,
                restore_settings: true,
                ..Default::default()
            })
            .unwrap();

        assert!(result.has_changes());
        assert!(result.restored.contains(&"settings.json".to_string()));
        assert!(result.restored.contains(&"items/item1".to_string()));

        // Verify restored data
        let items2 = manager2.sub_settings("items").unwrap();
        let loaded = items2.get_value("item1").unwrap();
        assert_eq!(loaded["name"], json!("First"));
    }

    #[test]
    fn test_restore_skip_existing() {
        let temp = tempdir().unwrap();

        // Create a backup with some data
        let config = SettingsConfig {
            config_dir: temp.path().join("config"),
            settings_file: "settings.json".into(),
            app_name: "test".into(),
            app_version: "1.0.0".into(),
            storage: JsonStorage::new(),
            enable_credentials: false,
            external_configs: Vec::new(),
            env_prefix: None,
            env_overrides_secrets: false,
            migrator: None, #[cfg(feature = "profiles")] profiles_enabled: false,
            #[cfg(feature = "profiles")]
            profile_migrator: crate::profiles::ProfileMigrator::None,
        };

        fs::create_dir_all(&config.config_dir).unwrap();
        fs::write(config.config_dir.join("settings.json"), "{}").unwrap();

        let manager = SettingsManager::new(config).unwrap();
        let backup_path = manager
            .backup()
            .create(BackupOptions {
                output_dir: temp.path().join("backups"),
                ..Default::default()
            })
            .unwrap();

        // Restore with overwrite disabled (settings already exist)
        let result = manager
            .backup()
            .restore(RestoreOptions {
                backup_path,
                overwrite_existing: false,
                ..Default::default()
            })
            .unwrap();

        // Should be skipped since it already exists
        assert!(result.skipped.contains(&"settings.json".to_string()));
    }
}
