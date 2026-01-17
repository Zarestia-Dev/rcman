//! Backup creation

use super::archive::{calculate_file_hash, create_rcman_container, create_zip_archive};
use super::types::{
    BackupAnalysis, BackupContents, BackupManifest, ExternalConfigProvider,
    SubSettingsManifestEntry,
};
use crate::backup::{BackupInfo, BackupIntegrity};
use crate::config::SettingsSchema;
use crate::error::{Error, Result};
use crate::manager::SettingsManager;
use crate::storage::StorageBackend;
use crate::sync::RwLockExt;
use crate::{BackupOptions, ExportType};
use log::{debug, info};
use std::fs;
use std::path::{Path, PathBuf};
use time::{OffsetDateTime, macros::format_description};

#[cfg(feature = "profiles")]
use crate::profiles::PROFILES_DIR;

/// Helper to collect settings files for backup (handles both profiled and flat)
/// Returns (`source_path`, `relative_dest_path`) pairs
fn collect_settings_files<S: StorageBackend, Schema: SettingsSchema>(
    config: &crate::config::SettingsConfig<S, Schema>,
    options: &BackupOptions,
) -> Vec<(PathBuf, PathBuf)> {
    let mut files = Vec::new();

    #[cfg(feature = "profiles")]
    if config.profiles_enabled {
        // Collect profile manifest
        let ext = config.storage.extension();
        let manifest_filename = format!(".profiles.{ext}");
        let manifest = config.config_dir.join(&manifest_filename);
        if manifest.exists() {
            files.push((manifest, PathBuf::from(&manifest_filename)));
        }

        // Collect profile settings
        let profiles_dir = config.config_dir.join(PROFILES_DIR);
        if let Ok(entries) = fs::read_dir(&profiles_dir) {
            for entry in entries.flatten() {
                let profile_name = entry.file_name().to_string_lossy().to_string();

                // Filter profiles if specified
                if !options.include_profiles.is_empty()
                    && !options.include_profiles.contains(&profile_name)
                {
                    continue;
                }

                let settings_file = entry.path().join(&config.settings_file);
                if settings_file.exists() {
                    let dest = PathBuf::from(PROFILES_DIR)
                        .join(&profile_name)
                        .join(&config.settings_file);
                    files.push((settings_file, dest));
                }
            }
        }
        return files;
    }

    // Non-profiled or feature disabled: just the single settings file
    #[cfg(not(feature = "profiles"))]
    let settings_path = config.settings_path();
    #[cfg(feature = "profiles")]
    let settings_path = config.settings_path();

    if settings_path.exists() {
        files.push((settings_path, PathBuf::from(&config.settings_file)));
    }

    files
}

/// Backup manager for creating and analyzing backups
pub struct BackupManager<'a, S: StorageBackend + 'static, Schema: SettingsSchema = ()> {
    /// Reference to the settings manager
    pub(crate) manager: &'a SettingsManager<S, Schema>,
}

impl<'a, S: StorageBackend + 'static, Schema: SettingsSchema> BackupManager<'a, S, Schema> {
    /// Create a new backup manager
    pub fn new(manager: &'a SettingsManager<S, Schema>) -> Self {
        Self { manager }
    }

    /// Register an external config provider
    pub fn register_external_provider(&self, provider: Box<dyn ExternalConfigProvider>) {
        self.manager.register_external_provider(provider);
    }

    /// Create a backup
    ///
    /// # Arguments
    ///
    /// * `options` - Backup options
    ///
    /// # Returns
    ///
    /// * `Result<PathBuf>` - Path to the created backup file
    ///
    /// # Errors
    ///
    /// * `Error::BackupFailed` - Backup failed
    /// * `Error::DirectoryCreate` - Failed to create directory
    /// * `Error::FileCreate` - Failed to create file
    /// * `Error::FileRead` - Failed to read file
    /// * `Error::FileWrite` - Failed to write file
    /// * `Error::InvalidPassword` - Invalid password
    /// * `Error::ZipCreate` - Failed to create zip file
    /// * `Error::ZipWrite` - Failed to write zip file
    pub fn create(&self, options: &BackupOptions) -> Result<PathBuf> {
        info!("Creating backup with options: {:?}", options.export_type);

        // Validate password if provided
        let password = validate_password(options.password.clone())?;

        // Create temp directory for gathering files
        let temp_dir = tempfile::tempdir().map_err(|e| Error::BackupFailed(e.to_string()))?;
        let export_dir = temp_dir.path().join("export");
        crate::security::ensure_secure_dir(&export_dir)?;

        // Gather files to backup
        let (contents, total_size) = self.gather_files(&export_dir, options)?;

        // Create inner data archive
        let data_filename = "data.zip";
        let inner_archive_path = temp_dir.path().join(data_filename);

        create_zip_archive(
            &export_dir,
            &inner_archive_path,
            options.on_progress.clone(),
            total_size,
            password.as_deref(),
        )?;

        // Calculate checksum
        let (checksum, _) = calculate_file_hash(&inner_archive_path)?;

        // Create manifest
        let manifest = BackupManifest {
            version: 1,
            backup: BackupInfo {
                app_name: self.manager.config().app_name.clone(),
                app_version: self.manager.config().app_version.clone(),
                created_at: OffsetDateTime::now_utc(),
                export_type: options.export_type.clone(),
                encrypted: password.is_some(),
                user_note: options.user_note.clone(),
            },
            contents,

            integrity: BackupIntegrity {
                sha256: Some(checksum),
                size_bytes: total_size,
                compressed_size_bytes: fs::metadata(&inner_archive_path).ok().map(|m| m.len()),
            },
        };

        // Serialize manifest using storage backend for format consistency
        // Note: Manifest is always stored as JSON for universal compatibility
        let manifest_json = serde_json::to_string_pretty(&manifest)
            .map_err(|e| Error::BackupFailed(e.to_string()))?;

        // Generate output filename
        let now = OffsetDateTime::now_utc();
        let timestamp_format = format_description!("[year][month][day]_[hour][minute][second]");
        let timestamp = now
            .format(&timestamp_format)
            .unwrap_or_else(|_| "unknown".to_string());
        let filename = if let Some(suffix) = &options.filename_suffix {
            format!(
                "{}_{}_{}.rcman",
                self.manager.config().app_name,
                timestamp,
                sanitize_filename(suffix)
            )
        } else {
            match &options.export_type {
                ExportType::Full => format!(
                    "{}_{}_full.rcman",
                    self.manager.config().app_name,
                    timestamp
                ),
                ExportType::SettingsOnly => {
                    // Try to infer a better suffix than "settings"
                    let suffix =
                        if !options.include_settings && options.include_sub_settings.len() == 1 {
                            // If exporting exactly one sub-setting (e.g. "remotes"), use that as suffix
                            &options.include_sub_settings[0]
                        } else {
                            "settings"
                        };

                    format!(
                        "{}_{}_{}.rcman",
                        self.manager.config().app_name,
                        timestamp,
                        suffix
                    )
                }
                ExportType::Single { name, .. } => {
                    format!(
                        "{}_{}_{}.rcman",
                        self.manager.config().app_name,
                        sanitize_filename(name),
                        timestamp
                    )
                }
            }
        };

        let output_path = options.output_dir.join(&filename);

        // Ensure output directory exists
        fs::create_dir_all(&options.output_dir).map_err(|e| Error::DirectoryCreate {
            path: options.output_dir.clone(),
            source: e,
        })?;

        // Create final .rcman container
        create_rcman_container(
            &output_path,
            &manifest_json,
            "manifest.json",
            &inner_archive_path,
            data_filename,
        )?;

        info!("Backup created: {:?}", output_path.display());
        Ok(output_path)
    }

    /// Gather files to backup
    fn gather_files(
        &self,
        export_dir: &Path,
        options: &BackupOptions,
    ) -> Result<(BackupContents, u64)> {
        let mut contents = BackupContents::default();
        let mut total_size = 0u64;

        // 1. Main settings
        let include_settings = (options.include_settings
            || matches!(options.export_type, ExportType::Full))
            && !matches!(options.export_type, ExportType::Single { .. });

        if include_settings {
            let (size, count) = self.gather_main_settings(export_dir, options)?;
            total_size += size;
            contents.file_count += count;
            contents.settings = true;
        }

        // 2. Sub-settings
        let sub_settings_to_backup = match &options.export_type {
            ExportType::Full | ExportType::SettingsOnly => options.include_sub_settings.clone(),
            ExportType::Single {
                settings_type,
                name,
            } => {
                // Handle single entry export inline (simple case)
                if let Ok(sub) = self.manager.sub_settings(settings_type) {
                    let sub_export_dir = export_dir.join(settings_type);
                    crate::error::create_dir(&sub_export_dir)?;

                    let value: serde_json::Value = sub.get_value(name)?;
                    // Use storage backend for format-agnostic export
                    let ext = self.manager.storage().extension();
                    let dest = sub_export_dir.join(format!("{name}.{ext}"));
                    let content = self.manager.storage().serialize(&value)?;
                    crate::error::write_file(&dest, &content)?;
                    total_size += content.len() as u64;
                    contents.file_count += 1;
                    contents.sub_settings.insert(
                        settings_type.clone(),
                        SubSettingsManifestEntry::MultiFile(vec![name.clone()]),
                    );
                    debug!("Added single entry: {settings_type}/{name}");
                }
                Vec::new()
            }
        };

        // Process each sub-settings type
        for sub_type in sub_settings_to_backup {
            if let Ok(sub) = self.manager.sub_settings(&sub_type) {
                let (size, count, manifest_entry) = self.gather_sub_settings(
                    export_dir,
                    &sub_type,
                    &sub,
                    self.manager.storage(),
                    options,
                )?;
                total_size += size;
                contents.file_count += count;
                if let Some(entry) = manifest_entry {
                    contents.sub_settings.insert(sub_type, entry);
                }
            }
        }

        // 3. External configs
        if !options.include_external_configs.is_empty() {
            let (size, count, configs) = self.gather_external_configs(export_dir, options)?;
            total_size += size;
            contents.file_count += count;
            contents.external_configs = configs;
        }

        Ok((contents, total_size))
    }

    /// Gather main settings files
    fn gather_main_settings(
        &self,
        export_dir: &Path,
        options: &BackupOptions,
    ) -> Result<(u64, u32)> {
        let mut total_size = 0u64;
        let mut file_count = 0u32;

        for (src, dest) in collect_settings_files(self.manager.config(), options) {
            let full_dest = export_dir.join(&dest);
            if let Some(parent) = full_dest.parent() {
                crate::error::create_dir(parent)?;
            }

            // Process and save with secret handling (prefix is empty for main settings)
            let size = self.process_and_save_settings(&src, &full_dest, "", options)?;

            total_size += size;
            file_count += 1;
            debug!("Added settings file: {}", dest.display());
        }

        Ok((total_size, file_count))
    }

    // Helper to read, process secrets, and write settings file
    fn process_and_save_settings(
        &self,
        src: &Path,
        dest: &Path,
        prefix: &str,
        options: &BackupOptions,
    ) -> Result<u64> {
        let content = std::fs::read(src).map_err(|e| Error::FileRead {
            path: src.to_path_buf(),
            source: e,
        })?;

        let content_str = String::from_utf8(content).map_err(|e| Error::FileRead {
            path: src.to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
        })?;

        // Use generic storage from manager config (assumed consistent)
        let storage = &self.manager.config().storage;
        let mut value: serde_json::Value = storage.deserialize(&content_str)?;

        self.traverse_secrets(
            &mut value,
            prefix,
            &Schema::get_metadata(),
            match options.secret_policy {
                crate::SecretBackupPolicy::Exclude => false,
                crate::SecretBackupPolicy::Include => true,
                crate::SecretBackupPolicy::EncryptedOnly => options.password.is_some(),
            },
        )?;

        let serialized = storage.serialize(&value)?;
        crate::error::write_file(dest, &serialized)?;

        Ok(serialized.len() as u64)
    }

    fn traverse_secrets(
        &self,
        value: &mut serde_json::Value,
        prefix: &str,
        metadata: &std::collections::HashMap<String, crate::SettingMetadata>,
        should_include: bool,
    ) -> Result<()> {
        self.traverse_secrets_impl(value, prefix, metadata, should_include, 0)
    }

    fn traverse_secrets_impl(
        &self,
        value: &mut serde_json::Value,
        prefix: &str,
        metadata: &std::collections::HashMap<String, crate::SettingMetadata>,
        should_include: bool,
        depth: usize,
    ) -> Result<()> {
        const MAX_DEPTH: usize = 32;
        if depth > MAX_DEPTH {
            return Err(Error::BackupFailed(format!(
                "JSON nesting exceeds maximum depth of {MAX_DEPTH}"
            )));
        }

        match value {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    let key = if prefix.is_empty() {
                        k.clone()
                    } else {
                        format!("{prefix}.{k}")
                    };

                    self.traverse_secrets_impl(v, &key, metadata, should_include, depth + 1)?;
                }
            }
            _ => {
                // Check if this is a secret - only relevant when keychain/encrypted-file features are enabled
                #[cfg(any(feature = "keychain", feature = "encrypted-file"))]
                if let Some(meta) = metadata.get(prefix) {
                    if meta.is_secret() {
                        if should_include {
                            // Try to fetch secret if simple value is null or default
                            // (It might be in keychain)
                            // Note: credentials() returns Option<&CredentialManager>, not Result
                            if let Some(creds) = self.manager.credentials() {
                                if let Ok(Some(secret)) = creds.get(prefix) {
                                    *value = serde_json::Value::String(secret);
                                }
                            }
                        } else {
                            // Redact
                            *value = serde_json::Value::Null;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Gather sub-settings files (handles both profiled and flat modes)
    fn gather_sub_settings(
        &self,
        export_dir: &Path,
        sub_type: &str,
        sub: &crate::sub_settings::SubSettings<S>,
        storage: &S,
        options: &BackupOptions,
    ) -> Result<(u64, u32, Option<SubSettingsManifestEntry>)> {
        // Check if profiles are enabled
        #[cfg(feature = "profiles")]
        let profiles_enabled = sub.profiles_enabled();
        #[cfg(not(feature = "profiles"))]
        let profiles_enabled = false;

        if profiles_enabled {
            #[cfg(feature = "profiles")]
            return Self::gather_profiled_sub_settings(export_dir, sub_type, sub, storage, options);
            #[cfg(not(feature = "profiles"))]
            unreachable!()
        }

        // Non-profiled sub-settings
        let sub_export_dir = export_dir.join(sub_type);

        if sub.is_single_file() {
            // Single-file mode
            if let Some(path) = sub.file_path() {
                if path.exists() {
                    crate::error::create_dir(&sub_export_dir)?;
                    let ext = sub.extension();
                    let dest = sub_export_dir.join(format!("{sub_type}.{ext}"));

                    // Process secrets: single file structure matches sub_type structure
                    // e.g. "remotes" -> { "gdrive": { ... } }
                    let size = self.process_and_save_settings(&path, &dest, sub_type, options)?;
                    debug!("📄 Added single-file sub-settings: {sub_type}");
                    return Ok((
                        size,
                        1,
                        Some(SubSettingsManifestEntry::SingleFile(format!(
                            "{sub_type}.{ext}",
                        ))),
                    ));
                }
            }
            Ok((0, 0, None))
        } else {
            // Multi-file mode
            crate::error::create_dir(&sub_export_dir)?;
            let mut total_size = 0u64;
            let mut items = Vec::new();

            for name in sub.list()? {
                if let Ok(mut value) = sub.get_value(&name) {
                    let ext = sub.extension();
                    let dest = sub_export_dir.join(format!("{name}.{ext}"));

                    // Process secrets for this item
                    let prefix = format!("{sub_type}.{name}");

                    self.traverse_secrets(
                        &mut value,
                        &prefix,
                        &Schema::get_metadata(),
                        match options.secret_policy {
                            crate::SecretBackupPolicy::Exclude => false,
                            crate::SecretBackupPolicy::Include => true,
                            crate::SecretBackupPolicy::EncryptedOnly => options.password.is_some(),
                        },
                    )?;

                    let content = storage.serialize(&value)?;
                    crate::error::write_file(&dest, &content)?;
                    total_size += content.len() as u64;
                    items.push(name);
                }
            }

            let count = u32::try_from(items.len()).unwrap_or(u32::MAX);
            debug!("Added sub-settings directory: {sub_type}");
            Ok((
                total_size,
                count,
                Some(SubSettingsManifestEntry::MultiFile(items)),
            ))
        }
    }

    /// Gather profiled sub-settings
    #[cfg(feature = "profiles")]
    fn gather_profiled_sub_settings(
        export_dir: &Path,
        sub_type: &str,
        sub: &crate::sub_settings::SubSettings<S>,
        storage: &S,
        options: &BackupOptions,
    ) -> Result<(u64, u32, Option<SubSettingsManifestEntry>)> {
        let sub_export_dir = export_dir.join(sub_type);
        let mut total_size = 0u64;
        let mut file_count = 0u32;

        // Copy .profiles.{ext}
        let root_path = sub.root_path();
        let ext = storage.extension();
        let manifest_filename = format!(".profiles.{ext}");
        let profiles_manifest = root_path.join(&manifest_filename);
        if profiles_manifest.exists() {
            crate::error::create_dir(&sub_export_dir)?;
            let dest = sub_export_dir.join(&manifest_filename);
            crate::error::copy_file(&profiles_manifest, &dest)?;
            total_size += crate::error::file_size(&dest);
            file_count += 1;
        }

        // Handle profiles folder
        let profiles_dir = root_path.join(PROFILES_DIR);
        if !profiles_dir.exists() {
            return Ok((total_size, file_count, None));
        }

        let dest_profiles_dir = sub_export_dir.join(PROFILES_DIR);
        crate::error::create_dir(&dest_profiles_dir)?;

        let mut profile_items: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();

        for entry in crate::error::read_dir(&profiles_dir)? {
            let entry = entry.map_err(|e| Error::DirectoryRead {
                path: profiles_dir.clone(),
                source: e,
            })?;

            let profile_name = entry.file_name().to_string_lossy().to_string();

            // Filter by requested profiles
            if !options.include_profiles.is_empty()
                && !options.include_profiles.contains(&profile_name)
            {
                continue;
            }

            let profile_path = entry.path();
            let profile_export_dir = dest_profiles_dir.join(&profile_name);
            crate::error::create_dir(&profile_export_dir)?;

            let mut items_in_profile = Vec::new();

            if let Ok(profile_entries) = fs::read_dir(&profile_path) {
                for item_entry in profile_entries.flatten() {
                    let path = item_entry.path();
                    // Use storage extension
                    if path.extension().and_then(|s| s.to_str()) == Some(storage.extension()) {
                        let dest = profile_export_dir.join(item_entry.file_name());
                        crate::error::copy_file(&path, &dest)?;
                        total_size += crate::error::file_size(&dest);
                        file_count += 1;

                        // Extract item name (without extension)
                        if let Some(item_name) = path.file_stem().and_then(|s| s.to_str()) {
                            items_in_profile.push(item_name.to_string());
                        }
                    }
                }
            }

            if !items_in_profile.is_empty() {
                profile_items.insert(profile_name, items_in_profile);
            }
        }

        let manifest_entry = if profile_items.is_empty() {
            None
        } else {
            let profiles_map = profile_items
                .into_iter()
                .map(|(profile_name, items)| {
                    let entry = if items.len() == 1 {
                        super::types::ProfileEntry::Single(items.into_iter().next().unwrap())
                    } else {
                        super::types::ProfileEntry::Multiple(items)
                    };
                    (profile_name, entry)
                })
                .collect();

            Some(SubSettingsManifestEntry::Profiled {
                profiles: profiles_map,
            })
        };

        Ok((total_size, file_count, manifest_entry))
    }

    /// Gather external config files
    fn gather_external_configs(
        &self,
        export_dir: &Path,
        options: &BackupOptions,
    ) -> Result<(u64, u32, Vec<String>)> {
        let providers = self.manager.external_providers.read_recovered()?;
        let mut all_configs = Vec::new();
        all_configs.extend(self.manager.config().external_configs.clone());
        for provider in providers.iter() {
            all_configs.extend(provider.get_configs());
        }

        let external_dir = export_dir.join("external");
        let mut total_size = 0u64;
        let mut file_count = 0u32;
        let mut config_ids = Vec::new();

        for config in all_configs {
            if !options.include_external_configs.contains(&config.id) {
                continue;
            }
            if !config.exists() {
                debug!("Skipping non-existent external config: {}", config.id);
                continue;
            }

            crate::error::create_dir(&external_dir)?;
            let dest = external_dir.join(&config.archive_filename);

            match &config.export_source {
                super::types::ExportSource::File(path) => {
                    crate::error::copy_file(path, &dest)?;
                }
                super::types::ExportSource::Command { program, args } => {
                    let output = std::process::Command::new(program)
                        .args(args)
                        .output()
                        .map_err(|e| {
                            Error::BackupFailed(format!("Failed to run command '{program}': {e}"))
                        })?;
                    if !output.status.success() {
                        return Err(Error::BackupFailed(format!(
                            "Command '{program}' failed with exit code {:?}",
                            output.status.code()
                        )));
                    }
                    crate::error::write_file(&dest, &output.stdout)?;
                }
                super::types::ExportSource::Content(bytes) => {
                    crate::error::write_file(&dest, bytes)?;
                }
            }

            total_size += crate::error::file_size(&dest);
            file_count += 1;
            config_ids.push(config.id.clone());
            debug!("Added external config: {}", config.id);
        }

        Ok((total_size, file_count, config_ids))
    }

    /// Analyze a backup file
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the backup file
    ///
    /// # Returns
    ///
    /// Returns a `BackupAnalysis` containing the result of the analysis operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the backup cannot be read or the analysis operation fails.
    pub fn analyze(&self, path: &Path) -> Result<BackupAnalysis> {
        if !path.exists() {
            return Err(Error::PathNotFound(path.display().to_string()));
        }

        // Read manifest from the .rcman file
        // Manifest is always JSON format for universal compatibility
        let manifest_bytes = super::archive::read_file_from_zip(path, "manifest.json")?;
        let manifest_str = String::from_utf8(manifest_bytes).map_err(|e| {
            Error::InvalidBackup(format!(
                "{}: Invalid manifest encoding: {}",
                path.display(),
                e
            ))
        })?;

        let manifest: BackupManifest = serde_json::from_str(&manifest_str).map_err(|e| {
            Error::InvalidBackup(format!("{}: Invalid manifest JSON: {}", path.display(), e))
        })?;

        let mut warnings = Vec::new();
        let mut is_valid = true;

        // Check manifest version compatibility
        if !super::types::is_manifest_version_supported(manifest.version) {
            warnings.push(format!(
                "Backup manifest version {} is not supported (supported: {}-{})",
                manifest.version,
                super::types::MANIFEST_VERSION_MIN_SUPPORTED,
                super::types::MANIFEST_VERSION_MAX_SUPPORTED
            ));
            is_valid = false;
        }

        // Check app version compatibility (warning only)
        if manifest.backup.app_version != self.manager.config().app_version {
            warnings.push(format!(
                "Backup was created with app version {}, current version is {}",
                manifest.backup.app_version,
                self.manager.config().app_version
            ));
        }

        // Verify encryption status by inspecting the actual data.zip
        // WARNING: optimizing this to not read the full file into RAM
        // requires refactoring archive.rs to support streaming reads.
        // For now, at least strictly limit the size or warn.
        let data_bytes = super::archive::read_file_from_zip(path, "data.zip")?;
        let temp_dir = tempfile::tempdir().map_err(|e| Error::BackupFailed(e.to_string()))?;
        let data_archive_path = temp_dir.path().join("data.zip");
        std::fs::write(&data_archive_path, data_bytes).map_err(|e| Error::FileWrite {
            path: data_archive_path.clone(),
            source: e,
        })?;

        let data_encrypted = super::archive::is_zip_encrypted(&data_archive_path)?;

        // Warn if manifest and actual encryption status mismatch
        if manifest.backup.encrypted != data_encrypted {
            warnings.push(format!(
                "Manifest claims encrypted={}, but data.zip encrypted={}",
                manifest.backup.encrypted, data_encrypted
            ));
        }

        Ok(BackupAnalysis {
            is_valid,
            requires_password: data_encrypted,
            warnings,
            // Display/convenience fields
            created_at: manifest
                .backup
                .created_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            backup_type: format_export_type(&manifest.backup.export_type),
            is_encrypted: manifest.backup.encrypted,
            format_version: manifest.version.to_string(),
            user_note: manifest.backup.user_note.clone(),
            manifest,
        })
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Validate password (minimum length, no whitespace-only)
fn validate_password(password: Option<String>) -> Result<Option<String>> {
    match password {
        Some(p) if p.trim().is_empty() => Err(Error::BackupFailed(
            "Password cannot be empty or whitespace-only".into(),
        )),
        Some(p) if p.len() < 4 => Err(Error::BackupFailed(
            "Password must be at least 4 characters".into(),
        )),
        other => Ok(other),
    }
}

/// Sanitize filename for safe file system usage
fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c => c,
        })
        .collect()
}

/// Format `ExportType` as a human-readable display string
fn format_export_type(export_type: &ExportType) -> String {
    match export_type {
        ExportType::Full => "Full Backup".into(),
        ExportType::SettingsOnly => "Settings Only".into(),
        ExportType::Single {
            settings_type,
            name,
        } => format!("Single {settings_type}: {name}"),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SettingsConfig;
    use crate::sub_settings::SubSettingsConfig;
    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn test_create_full_backup() {
        let temp = tempdir().unwrap();
        let config = SettingsConfig::builder("test-app", "1.0.0")
            .with_config_dir(temp.path())
            .build();

        let manager = SettingsManager::new(config).unwrap();

        // Create some settings
        fs::write(
            temp.path().join("settings.json"),
            r#"{"general": {"theme": "dark"}}"#,
        )
        .unwrap();

        // Register and populate sub-settings
        manager
            .register_sub_settings(SubSettingsConfig::new("profiles"))
            .unwrap();
        let profiles = manager.sub_settings("profiles").unwrap();
        profiles
            .set("default", &json!({"name": "Default"}))
            .unwrap();

        // Create backup
        let backup_dir = temp.path().join("backups");
        let backup = manager.backup();
        let backup_path = backup
            .create(&BackupOptions {
                output_dir: backup_dir.clone(),
                export_type: ExportType::Full,
                include_sub_settings: vec!["profiles".into()],
                ..Default::default()
            })
            .unwrap();

        assert!(backup_path.exists());
        assert!(backup_path.extension().unwrap() == "rcman");
    }

    #[test]
    fn test_analyze_backup() {
        let temp = tempdir().unwrap();
        let config = SettingsConfig::builder("test-app", "1.0.0")
            .with_config_dir(temp.path())
            .build();

        let manager = SettingsManager::new(config).unwrap();

        // Create minimal backup
        fs::write(temp.path().join("settings.json"), "{}").unwrap();

        let backup = manager.backup();
        let backup_path = backup
            .create(&BackupOptions {
                output_dir: temp.path().join("backups"),
                export_type: ExportType::SettingsOnly,
                ..Default::default()
            })
            .unwrap();

        // Analyze it
        let analysis = backup.analyze(&backup_path).unwrap();
        assert!(analysis.is_valid);
        assert!(!analysis.requires_password);
        assert_eq!(analysis.manifest.backup.app_name, "test-app");
    }

    #[test]
    fn test_validate_password() {
        assert!(validate_password(None).unwrap().is_none());
        assert!(validate_password(Some("valid".into())).unwrap().is_some());
        assert!(validate_password(Some("   ".into())).is_err());
        assert!(validate_password(Some("abc".into())).is_err()); // Too short
    }
    #[test]
    fn test_partial_backup_logic() {
        let temp = tempdir().unwrap();
        let config = SettingsConfig::builder("test-app", "1.0.0")
            .with_config_dir(temp.path())
            .build();

        let manager = SettingsManager::new(config).unwrap();

        // Create settings
        fs::write(
            temp.path().join("settings.json"),
            r#"{"general": {"theme": "dark"}}"#,
        )
        .unwrap();

        // Register and populate sub-settings
        manager
            .register_sub_settings(SubSettingsConfig::new("profiles"))
            .unwrap();
        let profiles = manager.sub_settings("profiles").unwrap();
        profiles
            .set("default", &json!({"name": "Default"}))
            .unwrap();

        // Create PARTIAL backup: No settings, only profiles
        let backup_dir = temp.path().join("backups");
        let backup = manager.backup();
        let backup_path = backup
            .create(&BackupOptions {
                output_dir: backup_dir.clone(),
                export_type: ExportType::SettingsOnly,
                include_settings: false, // EXPLICITLY DISABLED
                include_sub_settings: vec!["profiles".into()], // EXPLICITLY INCLUDED
                ..Default::default()
            })
            .unwrap();

        // Analyze it
        let analysis = backup.analyze(&backup_path).unwrap();

        // Assertions
        assert!(analysis.is_valid);
        assert!(
            !analysis.manifest.contents.settings,
            "Should NOT include settings.json"
        );
        assert!(
            analysis
                .manifest
                .contents
                .sub_settings
                .contains_key("profiles"),
            "Should include profiles"
        );

        // Verify physical file content
        // Note: Analysis reads manifest, but let's check archive if possible or trust manifest + extraction test
        // Since we don't have easy extraction helper in test utils without zip dep, rely on manifest which reflects gather_files actions.
    }
    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("normal"), "normal");
        assert_eq!(sanitize_filename("with/slash"), "with_slash");
        assert_eq!(sanitize_filename("file:name"), "file_name");
    }
}
