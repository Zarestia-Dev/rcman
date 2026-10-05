//! Backup/restore logic

use super::archive::{extract_zip_archive, read_file_from_zip};
use super::validate_backup_value;
use crate::config::SettingsSchema;
use crate::error::{Error, Result};
use crate::storage::StorageBackend;
use crate::utils::sync::RwLockExt;

use crate::backup::BackupAnalysis;
#[cfg(feature = "profiles")]
use crate::backup::SubSettingsManifestEntry;

use crate::RestoreOptions;
use log::{debug, info, warn};
use std::fs;
use std::path::Path;

#[cfg(feature = "profiles")]
use crate::profiles::PROFILES_DIR;

impl<S: StorageBackend + 'static, Schema: SettingsSchema> super::BackupManager<'_, S, Schema> {
    /// Restore selected archive contents using the destination's storage and vault.
    ///
    /// Selected managed payloads are validated before writes. A managed failure
    /// triggers rollback of journaled files and credentials; rollback failures are
    /// reported with the original error. This does not provide crash recovery.
    /// External imports run after managed commit and cannot roll it back.
    ///
    /// `dry_run` previews validation and selection without importing data. Inspect
    /// [`RestoreResult::has_conflicts`] for skipped or pending items.
    ///
    /// # Errors
    ///
    /// Returns errors for unsupported or corrupt archives, incorrect passwords,
    /// raw vault envelopes, invalid payloads, or unavailable credential storage.
    /// A locked destination vault returns `Error::ConfigLocked`; conflicting managed
    /// operations return `Error::Config` and may be retried after they finish.
    /// External import errors explicitly state that managed settings were restored.
    pub fn restore(&self, options: &RestoreOptions) -> Result<RestoreResult> {
        #[cfg(feature = "vault")]
        if self.manager.is_locked() {
            return Err(Error::ConfigLocked);
        }

        let mode_str = if options.flags.control.dry_run {
            "[DRY RUN] "
        } else {
            ""
        };
        info!(
            "{mode_str} Restoring from backup: {:?}",
            options.backup_path.display()
        );

        #[cfg(feature = "profiles")]
        for name in [
            options.restore_profile.as_deref(),
            options.restore_profile_as.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            crate::profiles::validate_profile_name(name)?;
        }

        // Analyze the backup first
        let analysis = self.analyze(&options.backup_path)?;

        // Create temp directory for extraction
        let temp_dir = tempfile::tempdir().map_err(|e| Error::RestoreFailed(e.to_string()))?;
        let extract_dir = temp_dir.path().join("extracted");

        let mut result = RestoreResult {
            is_dry_run: options.flags.control.dry_run,
            checksum_valid: Self::extract_backup(
                options,
                &analysis,
                temp_dir.path(),
                &extract_dir,
            )?,
            ..Default::default()
        };

        // Resolve providers once, before entering managed isolation. Provider
        // callbacks may call back into the application.
        let external_configs: std::collections::HashMap<_, _> = analysis
            .manifest
            .contents
            .external_configs
            .iter()
            .filter(|name| {
                options.restore_external_configs.is_empty()
                    || options.restore_external_configs.contains(name)
            })
            .filter_map(|name| {
                self.resolve_external_config(name)
                    .map(|config| (name.clone(), config))
            })
            .collect();
        let operation = super::transaction::exclusive(
            &self.manager.config().config_dir,
            #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
            self.manager
                .credentials()
                .map(crate::credentials::CredentialManager::service_name),
        )?;

        // Create context
        let ctx = RestoreContext {
            manager: self,
            options,
            extract_dir: &extract_dir,
            analysis: &analysis,
            mode_str,
            external_configs: &external_configs,
        };

        // Parse and validate every selected managed payload before touching live files.
        // Reuse the restore traversal so selection and overwrite rules stay identical.
        let mut preview_options = options.clone();
        preview_options.flags.control.dry_run = true;
        let preview = RestoreContext {
            options: &preview_options,
            ..ctx
        };
        let mut preview_result = preview.preview()?;
        if options.flags.control.dry_run {
            preview_result.is_dry_run = true;
            preview_result.checksum_valid = result.checksum_valid;
            return Ok(preview_result);
        }

        let transaction = super::transaction::Transaction::begin(&operation)?;
        let restored = (|| -> Result<()> {
            ctx.restore_main_settings(&mut result)?;
            ctx.restore_sub_settings_entries(&mut result)
        })();
        let notifications = transaction.finish(restored);
        self.manager.invalidate_cache();
        drop(operation);
        for notify in notifications? {
            notify();
        }

        // External targets may run arbitrary commands. They execute after the
        // managed transaction commits and cannot roll back managed settings.
        ctx.restore_external_configs_entries(&mut result)
            .map_err(|error| {
                Error::RestoreFailed(format!(
                    "Managed settings restored; external import failed: {error}"
                ))
            })?;

        info!(
            "Restore complete: {} restored, {} skipped",
            result.restored.len(),
            result.skipped.len()
        );

        Ok(result)
    }

    fn extract_backup(
        options: &RestoreOptions,
        analysis: &BackupAnalysis,
        temp_dir: &Path,
        extract_dir: &Path,
    ) -> Result<Option<bool>> {
        // Check manifest version compatibility
        if !analysis.is_valid {
            return Err(Error::InvalidBackup(format!(
                "{}: Backup manifest version {} is not supported (supported: {}-{})",
                options.backup_path.display(),
                analysis.manifest.version,
                super::types::MANIFEST_VERSION_MIN_SUPPORTED,
                super::types::MANIFEST_VERSION_MAX_SUPPORTED
            )));
        }

        // Check password requirement
        if analysis.requires_password && options.password.is_none() {
            return Err(Error::PasswordRequired);
        }

        // Extract the inner data archive
        let data_filename = "data.zip";
        let data_bytes = read_file_from_zip(&options.backup_path, data_filename)?;

        let data_archive_path = temp_dir.join(data_filename);
        fs::write(&data_archive_path, &data_bytes).map_err(|e| Error::FileWrite {
            path: data_archive_path.clone(),
            source: e,
        })?;

        // Verify checksum if requested and available
        let mut checksum_valid = None;

        if options.flags.control.verify_checksum {
            if let Some(ref expected_checksum) = analysis.manifest.integrity.sha256 {
                let (actual_checksum, _) = super::archive::calculate_file_hash(&data_archive_path)?;
                let is_valid = &actual_checksum == expected_checksum;
                checksum_valid = Some(is_valid);

                if !is_valid {
                    warn!(
                        "Checksum mismatch! Expected: {expected_checksum}, Got: {actual_checksum}"
                    );
                    return Err(Error::InvalidBackup(format!(
                        "{}: Data archive checksum verification failed - backup may be corrupted",
                        options.backup_path.display()
                    )));
                }
                debug!("Checksum verified: {actual_checksum}");
            } else {
                debug!("No checksum in manifest, skipping verification");
            }
        }

        // Extract data archive (always zip now)
        extract_zip_archive(&data_archive_path, extract_dir, options.password.as_deref())?;

        Ok(checksum_valid)
    }

    /// Get the path to an external config from a backup (for manual restoration)
    ///
    /// # Arguments
    ///
    /// * `backup_path` - The path to the backup file
    /// * `config_name` - The name of the external config to restore
    /// * `password` - The password for the backup file (if encrypted)
    ///
    /// # Returns
    ///
    /// Returns a vector of bytes containing the external config data.
    ///
    /// # Errors
    ///
    /// Returns an error if the backup cannot be read or the external config cannot be restored.
    pub fn get_external_config_from_backup(
        &self,
        backup_path: &Path,
        config_name: &str,
        password: Option<&str>,
    ) -> Result<Vec<u8>> {
        let analysis = self.analyze(backup_path)?;
        let data_filename = "data.zip";

        // Extract the data archive temporarily
        let temp_dir = tempfile::tempdir().map_err(|e| Error::RestoreFailed(e.to_string()))?;
        let data_bytes = read_file_from_zip(backup_path, data_filename)?;
        let data_archive_path = temp_dir.path().join(data_filename);
        fs::write(&data_archive_path, data_bytes).map_err(|e| Error::FileWrite {
            path: data_archive_path.clone(),
            source: e,
        })?;

        let extract_dir = temp_dir.path().join("extracted");

        // Extract (always zip now)
        extract_zip_archive(&data_archive_path, &extract_dir, password)?;

        let external_dir = extract_dir.join("external");

        let mut candidate_filenames = Vec::new();
        if let Some(file_name) = analysis
            .manifest
            .contents
            .external_config_files
            .get(config_name)
            .cloned()
        {
            candidate_filenames.push(file_name);
        }
        if let Some(config) = self.resolve_external_config(config_name) {
            candidate_filenames.push(config.archive_filename);
        }
        candidate_filenames.push(config_name.to_string());
        candidate_filenames.dedup();

        for filename in candidate_filenames {
            super::archive::archive_entry_name(Path::new(&filename))?;
            let config_path = external_dir.join(&filename);
            if config_path.exists() {
                return fs::read(&config_path).map_err(|e| Error::FileRead {
                    path: config_path,
                    source: e,
                });
            }
        }

        Err(Error::PathNotFound(
            external_dir.join(config_name).display().to_string(),
        ))
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
        {
            let providers = self
                .manager
                .external_providers
                .read_recovered()
                .ok()?
                .clone();
            for provider in &*providers {
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

struct RestoreContext<'a, S: StorageBackend + 'static, Schema: SettingsSchema> {
    manager: &'a super::BackupManager<'a, S, Schema>,
    options: &'a RestoreOptions,
    extract_dir: &'a Path,
    analysis: &'a BackupAnalysis,
    mode_str: &'a str,
    external_configs: &'a std::collections::HashMap<String, super::ExternalConfig>,
}

/// Helper context for sub-settings operations to reduce argument count
struct SubSettingsContext<'a, S: StorageBackend> {
    sub_type: &'a str,
    items_filter: &'a [String],
    sub: &'a crate::sub_settings::SubSettings<S>,
}

impl<S: StorageBackend + 'static, Schema: SettingsSchema> RestoreContext<'_, S, Schema> {
    fn preview(&self) -> Result<RestoreResult> {
        let mut result = RestoreResult::default();
        self.restore_main_settings(&mut result)?;
        self.restore_sub_settings_entries(&mut result)?;
        self.restore_external_configs_entries(&mut result)?;
        Ok(result)
    }

    fn validate_main_settings(&self, value: &serde_json::Value) -> Result<()> {
        if !value.is_object() {
            return Err(Error::InvalidBackup("Settings must be an object".into()));
        }
        self.validate_secret_destination(value, self.manager.manager.schema_metadata())?;
        for (key, metadata) in self.manager.manager.schema_metadata() {
            if let Some(value) = crate::utils::value::get_path(value, key) {
                metadata
                    .validate(value)
                    .map_err(|reason| Error::InvalidSettingValue {
                        key: key.clone(),
                        reason,
                    })?;
            }
        }
        Ok(())
    }

    fn validate_sub_entry(
        &self,
        sub: &crate::sub_settings::SubSettings<S>,
        name: &str,
        value: &serde_json::Value,
    ) -> Result<()> {
        if let Some(metadata) = sub.schema_metadata() {
            self.validate_secret_destination(value, &metadata)?;
        }
        sub.validate_against_schema(name, value)
    }

    fn validate_secret_destination(
        &self,
        value: &serde_json::Value,
        metadata: &crate::IndexMap<String, crate::SettingMetadata>,
    ) -> Result<()> {
        #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
        if self.manager.manager.credentials().is_some() {
            return Ok(());
        }
        if metadata.iter().any(|(key, meta)| {
            meta.is_secret() && crate::utils::value::get_path(value, key).is_some()
        }) {
            return Err(Error::InvalidBackup(
                "Restoring secret fields requires credential storage".into(),
            ));
        }
        Ok(())
    }

    #[cfg(feature = "profiles")]
    fn merge_profile_manifest(
        &self,
        content: &str,
        target: &Path,
        source_root: &Path,
    ) -> Result<crate::profiles::ProfileManifest> {
        let storage = self.manager.manager.storage();
        let source: crate::profiles::ProfileManifest = storage.deserialize(content)?;
        for name in source
            .profiles
            .iter()
            .chain(std::iter::once(&source.active))
        {
            crate::profiles::validate_profile_name(name)?;
        }
        if !source.has_profile(&source.active) {
            return Err(Error::InvalidBackup(
                "Active profile is absent from the profile manifest".into(),
            ));
        }
        // Retain the destination's active profile and unrelated profiles. Replacing
        // this manifest would leave existing manager/store paths pointing elsewhere.
        let mut merged: crate::profiles::ProfileManifest = if target.exists() {
            storage.read(target)?
        } else {
            crate::profiles::ProfileManifest::default()
        };
        for name in source.profiles {
            if self
                .options
                .restore_profile
                .as_ref()
                .is_some_and(|selected| selected != &name)
                || !source_root.join(PROFILES_DIR).join(&name).is_dir()
            {
                continue;
            }
            let target_name = if self.options.restore_profile.is_some() {
                self.options.restore_profile_as.as_ref().unwrap_or(&name)
            } else {
                &name
            };
            merged.add_profile(target_name.clone());
        }
        Ok(merged)
    }

    fn restore_main_settings(&self, result: &mut RestoreResult) -> Result<()> {
        if !self.options.flags.scope.restore_settings {
            return Ok(());
        }

        // Logic for profiles
        #[cfg(feature = "profiles")]
        if self.manager.manager.config().profiles_enabled
            && self.extract_dir.join(PROFILES_DIR).exists()
        {
            return self.restore_main_settings_profiles(result);
        }

        // Logic for legacy flat settings (either profiles disabled or feature off)
        if self.analysis.manifest.contents.settings {
            let source_dir = self.extract_dir.to_path_buf();
            #[cfg(feature = "profiles")]
            let source_dir = if self.extract_dir.join(PROFILES_DIR).exists() {
                let Some(profile) = &self.options.restore_profile else {
                    result.add_pending("settings", RestorePendingReason::ProfileSelectionRequired);
                    return Ok(());
                };
                let path = self.extract_dir.join(PROFILES_DIR).join(profile);
                if !path.is_dir() {
                    result.add_pending("settings", RestorePendingReason::MissingSourceProfile);
                    return Ok(());
                }
                path
            } else {
                source_dir
            };
            // Try to load settings from backup (agnostic of extension)
            if let Some((value, _ext)) =
                load_settings_agnostic(&source_dir, "settings", self.manager.manager.storage())?
            {
                self.validate_main_settings(&value)?;
                let settings_dest = self.manager.manager.settings_path()?;
                let dest_filename = settings_dest
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy();

                if settings_dest.exists() && !self.options.flags.control.overwrite_existing {
                    result
                        .add_skipped(dest_filename.to_string(), RestoreSkipReason::ExistsConflict);
                    warn!(
                        "{} Skipping {} (exists, overwrite disabled)",
                        self.mode_str, dest_filename
                    );
                } else if self.options.flags.control.dry_run {
                    result.restored.push(dest_filename.to_string());
                    debug!("{} Would restore {}", self.mode_str, dest_filename);
                } else {
                    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
                    let mut value = value;
                    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
                    {
                        #[cfg(feature = "profiles")]
                        let profile = if self.manager.manager.config().profiles_enabled {
                            Some(self.manager.manager.active_profile()?)
                        } else {
                            None
                        };
                        #[cfg(not(feature = "profiles"))]
                        let profile: Option<String> = None;
                        self.hydrate_main_settings_secrets(&mut value, profile.as_deref())?;
                    }

                    // Write using the configured storage backend (and encrypt if target vault is active)
                    self.manager
                        .manager
                        .write_settings_to_disk(&settings_dest, &value)?;
                    result.restored.push(dest_filename.to_string());
                    debug!("Restored {dest_filename}");
                }
            }
        }

        Ok(())
    }

    #[cfg(feature = "profiles")]
    fn restore_main_settings_profiles(&self, result: &mut RestoreResult) -> Result<()> {
        let config = self.manager.manager.config();

        // Restore .profiles.{ext}
        let ext = self.manager.manager.storage().extension();
        let manifest_filename = format!(".profiles.{ext}");
        let profiles_manifest = self.extract_dir.join(&manifest_filename);
        let target_manifest = config.config_dir.join(&manifest_filename);

        if profiles_manifest.exists() {
            let content =
                fs::read_to_string(&profiles_manifest).map_err(|source| Error::FileRead {
                    path: profiles_manifest.clone(),
                    source,
                })?;
            let manifest =
                self.merge_profile_manifest(&content, &target_manifest, self.extract_dir)?;
            if self.options.flags.control.dry_run {
                result.restored.push(manifest_filename.clone());
                debug!("{} Would restore {}", self.mode_str, manifest_filename);
            } else {
                super::transaction::capture_file(&target_manifest)?;
                self.manager
                    .manager
                    .storage()
                    .write(&target_manifest, &manifest)?;
                result.restored.push(manifest_filename);
            }
        }

        // Restore profiles
        let profiles_src_dir = self.extract_dir.join(PROFILES_DIR);
        if profiles_src_dir.exists() {
            let target_profiles_dir = config.config_dir.join(PROFILES_DIR);

            // Handle single profile restore request
            let profiles_to_restore = if let Some(ref profile) = self.options.restore_profile {
                vec![profile.clone()]
            } else {
                // Restore all found in source
                crate::error::read_dir(&profiles_src_dir)?
                    .filter_map(std::result::Result::ok)
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .collect()
            };

            for profile_name in profiles_to_restore {
                let src_profile_path = profiles_src_dir.join(&profile_name);
                if !src_profile_path.exists() {
                    warn!(
                        "{} Profile '{profile_name}' not found in backup",
                        self.mode_str
                    );
                    continue;
                }

                // Determine target profile name (rename if requested)
                let target_profile_name = if self.options.restore_profile.is_some() {
                    self.options
                        .restore_profile_as
                        .as_ref()
                        .unwrap_or(&profile_name)
                        .clone()
                } else {
                    profile_name.clone()
                };

                let target_profile_path = target_profiles_dir.join(&target_profile_name);

                let target_settings_file = &self.manager.manager.config().settings_file;
                let dest_settings = target_profile_path.join(target_settings_file);
                let restore_id = format!("profiles/{target_profile_name}/{target_settings_file}");

                if let Some((value, _ext)) = load_settings_agnostic(
                    &src_profile_path,
                    "settings",
                    self.manager.manager.storage(),
                )? {
                    self.validate_main_settings(&value)?;

                    if dest_settings.exists() && !self.options.flags.control.overwrite_existing {
                        result.add_skipped(restore_id, RestoreSkipReason::ExistsConflict);
                    } else if self.options.flags.control.dry_run {
                        result.restored.push(restore_id);
                        debug!(
                            "{} Would restore settings for profile {target_profile_name}",
                            self.mode_str
                        );
                    } else {
                        #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
                        let mut value = value;
                        #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
                        self.hydrate_main_settings_secrets(
                            &mut value,
                            Some(target_profile_name.as_str()),
                        )?;

                        self.manager
                            .manager
                            .write_settings_to_disk(&dest_settings, &value)?;
                        result.restored.push(restore_id);
                        debug!("Restored settings for profile {target_profile_name}");
                    }
                }
            }
        }
        Ok(())
    }

    fn restore_sub_settings_entries(&self, result: &mut RestoreResult) -> Result<()> {
        let sub_settings_to_restore = if self.options.restore_sub_settings.is_empty() {
            // Convert manifest entries to basic HashMap for processing
            self.analysis.manifest.contents.sub_settings_list()
        } else {
            self.options.restore_sub_settings.clone()
        };

        for (sub_type, items_filter) in sub_settings_to_restore {
            super::archive::archive_entry_name(Path::new(&sub_type))?;
            let sub_src_dir = self.extract_dir.join(&sub_type);

            // Get sub-settings handler
            let Ok(sub) = self.manager.manager.sub_settings(&sub_type) else {
                warn!("Sub-settings type '{sub_type}' not registered, skipping");
                result.add_skipped(sub_type, RestoreSkipReason::UnregisteredSubSettingsType);
                continue;
            };

            let sub_ctx = SubSettingsContext {
                sub_type: &sub_type,
                items_filter: &items_filter,
                sub: sub.as_ref(),
            };

            // Check if we are dealing with a profiled backup for this entry
            #[cfg(feature = "profiles")]
            if matches!(
                self.analysis.manifest.contents.sub_settings.get(&sub_type),
                Some(SubSettingsManifestEntry::Profiled { .. })
            ) {
                self.restore_profiled_sub_settings(&sub_ctx, &sub_src_dir, result)?;
                continue;
            }

            self.restore_flat_sub_settings(&sub_ctx, &sub_src_dir, result)?;
        }
        Ok(())
    }

    #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
    fn hydrate_main_settings_secrets(
        &self,
        value: &mut serde_json::Value,
        profile: Option<&str>,
    ) -> Result<()> {
        let Some(creds) = self.manager.manager.credentials() else {
            // No credential store: reject included secret fields rather than persist them in plaintext.
            if self
                .manager
                .manager
                .schema_metadata()
                .iter()
                .any(|(key, meta)| {
                    meta.is_secret() && crate::utils::value::get_path(value, key).is_some()
                })
            {
                return Err(Error::Credential(
                    "Restoring secret fields requires credential storage".into(),
                ));
            }
            return Ok(());
        };
        for (key, metadata) in self
            .manager
            .manager
            .schema_metadata()
            .iter()
            .filter(|(_, meta)| meta.is_secret())
        {
            let Some(secret) = crate::utils::value::get_path(value, key).cloned() else {
                continue;
            };
            if secret == metadata.default {
                creds.remove_with_profile(key, profile)?;
                creds.remove_tracked_secret(key, profile)?;
            } else {
                let text = match secret {
                    serde_json::Value::String(text) => text,
                    other => other.to_string(),
                };
                creds.store_with_profile(key, &text, profile)?;
                creds.add_tracked_secret(key, profile)?;
            }
            crate::utils::value::remove_path(value, key);
        }
        Ok(())
    }

    fn restore_flat_sub_settings(
        &self,
        sub_ctx: &SubSettingsContext<S>,
        sub_src_dir: &Path,
        result: &mut RestoreResult,
    ) -> Result<()> {
        let ext = sub_ctx.sub.extension();
        let sub_single_file_src = self
            .extract_dir
            .join(format!("{}.{}", sub_ctx.sub_type, ext));

        // Collect entries to restore from either directory or single file
        let mut entries_to_restore: Vec<(String, serde_json::Value)> = Vec::new();

        if sub_single_file_src.exists() {
            // Restore from single file
            let content =
                fs::read_to_string(&sub_single_file_src).map_err(|e| Error::FileRead {
                    path: sub_single_file_src.clone(),
                    source: e,
                })?;

            let file_data: serde_json::Value = self
                .manager
                .manager
                .storage()
                .deserialize(&content)
                .map_err(|e| Error::Parse(e.to_string()))?;

            validate_backup_value(&file_data)?;
            if let Some(obj) = file_data.as_object() {
                for (key, value) in obj {
                    entries_to_restore.push((key.clone(), value.clone()));
                }
            }
        } else if sub_src_dir.exists() {
            // Restore from directory
            for entry in crate::error::read_dir(sub_src_dir)? {
                let entry = entry.map_err(|e| Error::FileRead {
                    path: sub_src_dir.to_path_buf(),
                    source: e,
                })?;

                let file_name = entry.file_name();
                let name_str = file_name.to_string_lossy();
                let ext_str = format!(".{ext}");

                if !name_str.ends_with(&ext_str) {
                    continue;
                }

                let entry_name = name_str
                    .strip_suffix(&ext_str)
                    .unwrap_or(&name_str)
                    .to_string();

                let content = fs::read_to_string(entry.path()).map_err(|e| Error::FileRead {
                    path: entry.path(),
                    source: e,
                })?;

                let value: serde_json::Value =
                    self.manager.manager.storage().deserialize(&content)?;
                validate_backup_value(&value)?;

                // If this is the main file for a SingleFile sub-setting (e.g. connections.json inside connections/),
                // flatten its entries so we restore "Local" and "Remote" instead of "connections" -> {...}
                if sub_ctx.sub.is_single_file() && entry_name == sub_ctx.sub_type {
                    if let serde_json::Value::Object(map) = value {
                        entries_to_restore.extend(map);
                    }
                } else {
                    entries_to_restore.push((entry_name, value));
                }
            }
        }

        // Process the collected entries
        for (entry_name, value) in entries_to_restore {
            // Filter by items if specified
            if !sub_ctx.items_filter.is_empty() && !sub_ctx.items_filter.contains(&entry_name) {
                continue;
            }

            let entry_id = format!("{}/{}", sub_ctx.sub_type, entry_name);

            // Check if exists
            if !self.options.flags.control.overwrite_existing
                && sub_ctx
                    .sub
                    .backup_entries(&sub_ctx.sub.directory())?
                    .contains_key(&entry_name)
            {
                result.add_skipped(entry_id, RestoreSkipReason::ExistsConflict);
                continue;
            }

            validate_backup_value(&value)?;
            self.validate_sub_entry(sub_ctx.sub, &entry_name, &value)?;
            if self.options.flags.control.dry_run {
                result.restored.push(entry_id.clone());
                debug!("{} Would restore {entry_id}", self.mode_str);
                continue;
            }

            sub_ctx.sub.set(&entry_name, &value)?;

            result.restored.push(entry_id.clone());
            debug!("Restored {entry_id}");
        }
        Ok(())
    }

    #[cfg(feature = "profiles")]
    fn restore_profiled_sub_settings(
        &self,
        sub_ctx: &SubSettingsContext<S>,
        sub_src_dir: &Path,
        result: &mut RestoreResult,
    ) -> Result<()> {
        let target_profiles_enabled = sub_ctx.sub.profiles_enabled();

        // Restore .profiles.{ext} if target supports it
        if target_profiles_enabled {
            let ext = sub_ctx.sub.storage().extension();

            let manifest_filename = format!(".profiles.{ext}");
            let profiles_manifest = sub_src_dir.join(&manifest_filename);
            let target_root = sub_ctx.sub.root_path();
            let target_manifest = target_root.join(&manifest_filename);

            if profiles_manifest.exists() {
                let content =
                    fs::read_to_string(&profiles_manifest).map_err(|source| Error::FileRead {
                        path: profiles_manifest.clone(),
                        source,
                    })?;
                let manifest =
                    self.merge_profile_manifest(&content, &target_manifest, sub_src_dir)?;
                if !self.options.flags.control.dry_run {
                    super::transaction::capture_file(&target_manifest)?;
                    sub_ctx.sub.storage().write(&target_manifest, &manifest)?;
                }
            }

            // Iterate profiles
            let profiles_src_dir = sub_src_dir.join(PROFILES_DIR);

            if profiles_src_dir.exists() {
                let profiles_to_restore = if let Some(ref profile) = self.options.restore_profile {
                    vec![profile.clone()]
                } else {
                    crate::error::read_dir(&profiles_src_dir)?
                        .filter_map(std::result::Result::ok)
                        .map(|e| e.file_name().to_string_lossy().to_string())
                        .collect()
                };

                for profile_name in profiles_to_restore {
                    self.restore_single_profile_sub_setting(
                        sub_ctx,
                        &profiles_src_dir,
                        &profile_name,
                        result,
                    )?;
                }
            }
        } else {
            // Profiled backup -> Flat target?
            // If specific profile requested, we can flatten it to root.
            if let Some(ref src_profile) = self.options.restore_profile {
                let profiles_src_dir = sub_src_dir.join(PROFILES_DIR);
                let src_profile_path = profiles_src_dir.join(src_profile);

                if src_profile_path.exists() {
                    self.restore_flattened_profile_content(sub_ctx, &src_profile_path, result)?;
                }
            } else {
                warn!(
                    "Cannot restore profiled backup of '{}' to non-profiled target without specifying --restore-profile",
                    sub_ctx.sub_type
                );
                result.add_pending(
                    sub_ctx.sub_type,
                    RestorePendingReason::ProfileSelectionRequired,
                );
            }
        }
        Ok(())
    }

    #[cfg(feature = "profiles")]
    fn restore_single_profile_sub_setting(
        &self,
        sub_ctx: &SubSettingsContext<S>,
        profiles_src_dir: &Path,
        profile_name: &str,
        result: &mut RestoreResult,
    ) -> Result<()> {
        let src_profile_path = profiles_src_dir.join(profile_name);
        if !src_profile_path.exists() {
            result.add_pending(
                format!("{}/{profile_name}", sub_ctx.sub_type),
                RestorePendingReason::MissingSourceProfile,
            );
            return Ok(());
        }

        let target_root = sub_ctx.sub.root_path();
        let target_profiles_dir = target_root.join(PROFILES_DIR);

        let target_profile_name = if self.options.restore_profile.is_some() {
            self.options
                .restore_profile_as
                .as_ref()
                .unwrap_or(&profile_name.to_string())
                .clone()
        } else {
            profile_name.to_string()
        };

        let dest_profile_path = target_profiles_dir.join(&target_profile_name);

        let existing = if self.options.flags.control.overwrite_existing {
            std::collections::HashMap::new()
        } else {
            sub_ctx.sub.backup_entries(&dest_profile_path)?
        };
        let store = sub_ctx.sub.backup_store(&dest_profile_path);
        for entry in crate::error::read_dir(&src_profile_path)? {
            let entry = entry.map_err(|source| Error::DirectoryRead {
                path: src_profile_path.clone(),
                source,
            })?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some(sub_ctx.sub.extension()) {
                continue;
            }
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or_else(|| Error::InvalidBackup("Invalid sub-settings entry name".into()))?;
            let content = fs::read_to_string(&path).map_err(|source| Error::FileRead {
                path: path.clone(),
                source,
            })?;
            let value: serde_json::Value = sub_ctx.sub.storage().deserialize(&content)?;
            validate_backup_value(&value)?;
            let entries = if sub_ctx.sub.is_single_file() {
                value
                    .as_object()
                    .cloned()
                    .ok_or_else(|| Error::InvalidBackup("Expected sub-settings entries".into()))?
            } else {
                serde_json::Map::from_iter([(stem.to_owned(), value)])
            };
            for (name, mut value) in entries {
                if !sub_ctx.items_filter.is_empty() && !sub_ctx.items_filter.contains(&name) {
                    continue;
                }
                let id = format!("{}/{target_profile_name}/{name}", sub_ctx.sub_type);
                if existing.contains_key(&name) {
                    result.add_skipped(id, RestoreSkipReason::ExistsConflict);
                    continue;
                }
                self.prepare_profile_entry(sub_ctx.sub, &name, &mut value, &target_profile_name)?;
                if !self.options.flags.control.dry_run {
                    store.set(&name, value)?;
                }
                result.restored.push(id);
            }
        }
        Ok(())
    }

    #[cfg(feature = "profiles")]
    fn prepare_profile_entry(
        &self,
        sub: &crate::sub_settings::SubSettings<S>,
        name: &str,
        value: &mut serde_json::Value,
        profile: &str,
    ) -> Result<()> {
        #[cfg(not(any(feature = "keychain", feature = "encrypted-file")))]
        let _ = profile;
        validate_backup_value(value)?;
        self.validate_sub_entry(sub, name, value)?;
        #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
        if !self.options.flags.control.dry_run {
            sub.extract_and_store_secrets_for_profile(name, value, Some(profile))?;
        }
        Ok(())
    }

    #[cfg(feature = "profiles")]
    fn restore_flattened_profile_content(
        &self,
        sub_ctx: &SubSettingsContext<S>,
        src_profile_path: &Path,
        result: &mut RestoreResult,
    ) -> Result<()> {
        // Restore items from this profile to active flat root
        {
            let entries = crate::error::read_dir(src_profile_path)?;
            let ext = sub_ctx.sub.extension();
            for entry in entries {
                let entry = entry.map_err(|source| Error::DirectoryRead {
                    path: src_profile_path.to_path_buf(),
                    source,
                })?;
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some(ext) {
                    let stem = path
                        .file_stem()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_default();
                    if !sub_ctx.sub.is_single_file()
                        && !sub_ctx.items_filter.is_empty()
                        && !sub_ctx.items_filter.contains(&stem)
                    {
                        continue;
                    }

                    let content = fs::read_to_string(&path).map_err(|e| Error::FileRead {
                        path: path.clone(),
                        source: e,
                    })?;
                    let value: serde_json::Value =
                        self.manager.manager.storage().deserialize(&content)?;
                    validate_backup_value(&value)?;

                    // Handle SingleFile sub-settings being restored from a profile containing the single file
                    if sub_ctx.sub.is_single_file() && stem == sub_ctx.sub_type {
                        if let serde_json::Value::Object(map) = value {
                            for (k, v) in map {
                                if !sub_ctx.items_filter.is_empty()
                                    && !sub_ctx.items_filter.contains(&k)
                                {
                                    continue;
                                }
                                validate_backup_value(&v)?;
                                self.validate_sub_entry(sub_ctx.sub, &k, &v)?;
                                let item_id = format!("{}/{k}", sub_ctx.sub_type);

                                if sub_ctx
                                    .sub
                                    .backup_entries(&sub_ctx.sub.directory())?
                                    .contains_key(&k)
                                    && !self.options.flags.control.overwrite_existing
                                {
                                    result.add_skipped(item_id, RestoreSkipReason::ExistsConflict);
                                } else if self.options.flags.control.dry_run {
                                    result.restored.push(item_id.clone());
                                    debug!("{} Would restore flattened {item_id}", self.mode_str);
                                } else {
                                    sub_ctx.sub.set(&k, &v)?;
                                    result.restored.push(item_id.clone());
                                    debug!("Restored flattened {item_id}");
                                }
                            }
                        }
                        continue;
                    }

                    self.validate_sub_entry(sub_ctx.sub, &stem, &value)?;
                    let entry_id = format!("{}/{stem}", sub_ctx.sub_type);

                    if sub_ctx
                        .sub
                        .backup_entries(&sub_ctx.sub.directory())?
                        .contains_key(&stem)
                        && !self.options.flags.control.overwrite_existing
                    {
                        result.add_skipped(entry_id, RestoreSkipReason::ExistsConflict);
                    } else if self.options.flags.control.dry_run {
                        result.restored.push(entry_id.clone());
                        debug!("{} Would restore flattened {entry_id}", self.mode_str);
                    } else {
                        sub_ctx.sub.set(&stem, &value)?;
                        result.restored.push(entry_id.clone());
                        debug!("Restored flattened {entry_id}");
                    }
                }
            }
        }
        Ok(())
    }

    fn restore_external_configs_entries(&self, result: &mut RestoreResult) -> Result<()> {
        let external_dir = self.extract_dir.join("external");
        if external_dir.exists() {
            for config_name in &self.analysis.manifest.contents.external_configs {
                // Skip if specific configs requested and this isn't one
                if !self.options.restore_external_configs.is_empty()
                    && !self.options.restore_external_configs.contains(config_name)
                {
                    continue;
                }

                let archive_filename = match self
                    .analysis
                    .manifest
                    .contents
                    .external_config_files
                    .get(config_name)
                {
                    Some(file_name) => file_name.as_str(),
                    None => config_name,
                };

                self.restore_single_external_config(
                    config_name,
                    archive_filename,
                    &external_dir,
                    result,
                )?;
            }
        }
        Ok(())
    }

    fn restore_single_external_config(
        &self,
        config_name: &str,
        archive_filename: &str,
        external_dir: &Path,
        result: &mut RestoreResult,
    ) -> Result<()> {
        if let Some(external_config) = self.external_configs.get(config_name) {
            let data = Self::read_external_backup_data(
                external_dir,
                config_name,
                archive_filename,
                &external_config.archive_filename,
            )?;

            // Handle different import targets
            match &external_config.import_target {
                super::types::ImportTarget::ReadOnly => {
                    debug!("Skipping read-only external config: {config_name}");
                    result.add_skipped(
                        config_name.to_string(),
                        RestoreSkipReason::ReadOnlyImportTarget,
                    );
                }
                super::types::ImportTarget::File(dest_path) => {
                    if dest_path.exists() && !self.options.flags.control.overwrite_existing {
                        result.add_skipped(
                            config_name.to_string(),
                            RestoreSkipReason::ExistsConflict,
                        );
                        debug!("{} Skipping external {config_name} (exists)", self.mode_str);
                    } else if self.options.flags.control.dry_run {
                        result.restored.push(config_name.to_string());
                        debug!("{} Would restore external {config_name}", self.mode_str);
                    } else {
                        Self::restore_external_file(dest_path, &data)?;
                        result.restored.push(config_name.to_string());
                        debug!("Restored external {config_name}");
                    }
                }
                super::types::ImportTarget::Command { program, args } => {
                    if self.options.flags.control.dry_run {
                        result.restored.push(config_name.to_string());
                        debug!("{} Would pipe to command: {program}", self.mode_str);
                    } else {
                        use std::io::Write;
                        use std::process::{Command, Stdio};

                        let mut child = Command::new(program)
                            .args(args)
                            .stdin(Stdio::piped())
                            .spawn()
                            .map_err(|e| {
                                Error::BackupFailed(format!(
                                    "Failed to spawn command '{program}': {e}"
                                ))
                            })?;

                        if let Some(mut stdin) = child.stdin.take() {
                            stdin.write_all(&data).map_err(|e| {
                                Error::BackupFailed(format!(
                                    "Failed to write to command stdin: {e}"
                                ))
                            })?;
                        }

                        let status = child.wait().map_err(|e| {
                            Error::BackupFailed(format!("Command '{program}' failed: {e}"))
                        })?;

                        if !status.success() {
                            return Err(Error::BackupFailed(format!(
                                "Command '{program}' exited with code {:?}",
                                status.code()
                            )));
                        }

                        result.restored.push(config_name.to_string());
                        debug!("Restored external {config_name} via command");
                    }
                }
                super::types::ImportTarget::Handler(handler) => {
                    if self.options.flags.control.dry_run {
                        result.restored.push(config_name.to_string());
                        debug!(
                            "{} Would call custom handler for {config_name}",
                            self.mode_str
                        );
                    } else {
                        handler(&data)?;
                        result.restored.push(config_name.to_string());
                        debug!("Restored external {config_name} via handler");
                    }
                }
            }
        } else {
            result.add_pending(
                config_name.to_string(),
                RestorePendingReason::UnknownExternalConfig,
            );
            warn!("Unknown external config ID: {config_name}, requires manual restore");
        }
        Ok(())
    }

    fn restore_external_file(dest_path: &Path, data: &[u8]) -> Result<()> {
        use std::io::Write;
        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::FileWrite {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
        let parent = dest_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut staged = tempfile::NamedTempFile::new_in(parent)
            .map_err(|e| Error::RestoreFailed(e.to_string()))?;
        staged
            .write_all(data)
            .and_then(|()| staged.as_file().sync_all())
            .map_err(|source| Error::FileWrite {
                path: dest_path.to_path_buf(),
                source,
            })?;
        staged
            .persist(dest_path)
            .map_err(|e| Error::RestoreFailed(e.to_string()))?;
        Ok(())
    }

    fn read_external_backup_data(
        external_dir: &Path,
        config_name: &str,
        archive_filename: &str,
        fallback_archive_filename: &str,
    ) -> Result<Vec<u8>> {
        let mut candidate_filenames = vec![archive_filename.to_string()];
        candidate_filenames.push(fallback_archive_filename.to_string());
        candidate_filenames.push(config_name.to_string());
        candidate_filenames.dedup();

        let mut last_candidate_path = None;
        for filename in candidate_filenames {
            super::archive::archive_entry_name(Path::new(&filename))?;
            let src = external_dir.join(filename);
            last_candidate_path = Some(src.clone());
            if src.exists() {
                return fs::read(&src).map_err(|e| Error::FileRead {
                    path: src,
                    source: e,
                });
            }
        }

        Err(Error::PathNotFound(
            last_candidate_path
                .unwrap_or_else(|| external_dir.join(config_name))
                .display()
                .to_string(),
        ))
    }
}

/// Attempt to load settings from a file, trying generic extensions
fn load_settings_agnostic<S: StorageBackend>(
    dir: &Path,
    stem: &str,
    storage: &S,
) -> Result<Option<(serde_json::Value, String)>> {
    // Try configured storage extension
    let current_ext = storage.extension();
    let current_path = dir.join(format!("{stem}.{current_ext}"));
    if current_path.exists() {
        let content = fs::read_to_string(&current_path).map_err(|e| Error::FileRead {
            path: current_path.clone(),
            source: e,
        })?;
        // Try deserializing using storage backend first
        // If it fails, maybe try generic? But usually if extension matches, format should match.
        // We map deserialize error to generic Parse error
        // Note: we need explicit type annotation for deserialize
        let val: serde_json::Value = storage.deserialize(&content)?;
        validate_backup_value(&val)?;
        return Ok(Some((val, current_ext.to_string())));
    }

    // 1. Try JSON (Fallback)
    if current_ext != "json" {
        let json_path = dir.join(format!("{stem}.json"));
        if json_path.exists() {
            let content = fs::read_to_string(&json_path).map_err(|e| Error::FileRead {
                path: json_path.clone(),
                source: e,
            })?;
            let val: serde_json::Value =
                serde_json::from_str(&content).map_err(|e| Error::Parse(e.to_string()))?;
            validate_backup_value(&val)?;
            return Ok(Some((val, "json".to_string())));
        }
    }

    // 2. Try TOML (if enabled)
    #[cfg(feature = "toml")]
    {
        let toml_path = dir.join(format!("{stem}.toml"));
        if toml_path.exists() {
            let content = fs::read_to_string(&toml_path).map_err(|e| Error::FileRead {
                path: toml_path.clone(),
                source: e,
            })?;
            // toml deserializes into serde_json::Value via Serde
            let val: serde_json::Value =
                toml::from_str(&content).map_err(|e| Error::Parse(e.to_string()))?;
            validate_backup_value(&val)?;
            return Ok(Some((val, "toml".to_string())));
        }
    }

    Ok(None)
}

/// Result of a restore operation
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RestoreSkipReason {
    /// Target entry already exists and overwrite is disabled.
    ExistsConflict,
    /// External config import target is read-only.
    ReadOnlyImportTarget,
    /// Requested sub-settings type was not registered in target manager.
    UnregisteredSubSettingsType,
}

/// Detailed skipped restore item with reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreSkippedItem {
    /// Item identifier (same value as in `RestoreResult::skipped`).
    pub id: String,
    /// Why this item was skipped.
    pub reason: RestoreSkipReason,
}

/// Pending restore reasons that require manual handling or missing source data.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RestorePendingReason {
    /// External config is present in backup but not registered in target.
    UnknownExternalConfig,
    /// Profiled backup requires selecting a source profile for flat targets.
    ProfileSelectionRequired,
    /// Requested source profile was not present in backup contents.
    MissingSourceProfile,
}

/// Detailed pending restore item with reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestorePendingItem {
    /// Item identifier (same value as in `RestoreResult::external_pending`).
    pub id: String,
    /// Why this item is pending.
    pub reason: RestorePendingReason,
}

#[derive(Debug, Default)]
pub struct RestoreResult {
    /// Items that were restored
    pub restored: Vec<String>,

    /// Items that were skipped (already exist)
    pub skipped: Vec<String>,

    /// Detailed skip records with reason for conflict visibility.
    pub skipped_details: Vec<RestoreSkippedItem>,

    /// External configs that need manual handling
    pub external_pending: Vec<String>,

    /// Detailed pending records with reason for manual handling visibility.
    pub pending_details: Vec<RestorePendingItem>,

    /// Whether this was a dry run (no actual changes made)
    pub is_dry_run: bool,

    /// Whether the checksum was verified successfully
    pub checksum_valid: Option<bool>,
}

impl RestoreResult {
    fn add_skipped(&mut self, id: impl Into<String>, reason: RestoreSkipReason) {
        let id = id.into();
        self.skipped.push(id.clone());
        self.skipped_details.push(RestoreSkippedItem { id, reason });
    }

    fn add_pending(&mut self, id: impl Into<String>, reason: RestorePendingReason) {
        let id = id.into();
        self.external_pending.push(id.clone());
        self.pending_details.push(RestorePendingItem { id, reason });
    }

    /// Check if anything was restored
    #[must_use]
    pub fn has_changes(&self) -> bool {
        !self.restored.is_empty()
    }

    /// Check if restore had any skipped or pending conflicts.
    #[must_use]
    pub fn has_conflicts(&self) -> bool {
        !self.skipped_details.is_empty() || !self.pending_details.is_empty()
    }

    /// Count skipped items by reason.
    #[must_use]
    pub fn skipped_count_by_reason(&self, reason: RestoreSkipReason) -> usize {
        self.skipped_details
            .iter()
            .filter(|item| item.reason == reason)
            .count()
    }

    /// Count pending items by reason.
    #[must_use]
    pub fn pending_count_by_reason(&self, reason: RestorePendingReason) -> usize {
        self.pending_details
            .iter()
            .filter(|item| item.reason == reason)
            .count()
    }

    /// Return skipped item ids for a specific reason.
    #[must_use]
    pub fn skipped_ids_by_reason(&self, reason: RestoreSkipReason) -> Vec<&str> {
        self.skipped_details
            .iter()
            .filter(|item| item.reason == reason)
            .map(|item| item.id.as_str())
            .collect()
    }

    /// Return pending item ids for a specific reason.
    #[must_use]
    pub fn pending_ids_by_reason(&self, reason: RestorePendingReason) -> Vec<&str> {
        self.pending_details
            .iter()
            .filter(|item| item.reason == reason)
            .map(|item| item.id.as_str())
            .collect()
    }

    /// Get total item count
    #[must_use]
    pub fn total(&self) -> usize {
        self.restored.len() + self.skipped.len()
    }

    /// Would this restore have made changes (for dry run results)
    #[must_use]
    pub fn would_change(&self) -> bool {
        !self.restored.is_empty() || self.checksum_valid == Some(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_result_reports_conflicts_and_reason_counts() {
        let mut result = RestoreResult::default();
        assert!(!result.has_conflicts());

        result.add_skipped("settings.json", RestoreSkipReason::ExistsConflict);
        result.add_skipped("external_ro", RestoreSkipReason::ReadOnlyImportTarget);
        result.add_pending(
            "external_missing",
            RestorePendingReason::UnknownExternalConfig,
        );

        assert!(result.has_conflicts());
        assert_eq!(
            result.skipped_count_by_reason(RestoreSkipReason::ExistsConflict),
            1
        );
        assert_eq!(
            result.skipped_count_by_reason(RestoreSkipReason::ReadOnlyImportTarget),
            1
        );
        assert_eq!(
            result.pending_count_by_reason(RestorePendingReason::UnknownExternalConfig),
            1
        );
        assert_eq!(
            result.pending_count_by_reason(RestorePendingReason::MissingSourceProfile),
            0
        );
    }

    #[test]
    fn restore_result_returns_ids_by_reason() {
        let mut result = RestoreResult::default();

        result.add_skipped("a", RestoreSkipReason::ExistsConflict);
        result.add_skipped("b", RestoreSkipReason::ReadOnlyImportTarget);
        result.add_skipped("c", RestoreSkipReason::ExistsConflict);

        result.add_pending("p1", RestorePendingReason::UnknownExternalConfig);
        result.add_pending("p2", RestorePendingReason::ProfileSelectionRequired);

        assert_eq!(
            result.skipped_ids_by_reason(RestoreSkipReason::ExistsConflict),
            vec!["a", "c"]
        );
        assert_eq!(
            result.pending_ids_by_reason(RestorePendingReason::ProfileSelectionRequired),
            vec!["p2"]
        );
    }
}
