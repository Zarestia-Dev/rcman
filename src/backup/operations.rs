//! Backup creation

use super::archive::{calculate_file_hash, create_rcman_container, create_zip_archive};
use super::types::*;
use crate::config::SettingsSchema;
use crate::error::{Error, Result};
use crate::manager::SettingsManager;
use crate::storage::StorageBackend;
use chrono::Utc;
use log::{debug, info};
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(feature = "profiles")]
use crate::profiles::{MANIFEST_FILE, PROFILES_DIR};

/// Helper to collect settings files for backup (handles both profiled and flat)
/// Returns (source_path, relative_dest_path) pairs
fn collect_settings_files(
    config: &crate::config::SettingsConfig<impl StorageBackend>,
    #[cfg_attr(not(feature = "profiles"), allow(unused_variables))] options: &BackupOptions,
) -> Result<Vec<(PathBuf, PathBuf)>> {
    let mut files = Vec::new();

    #[cfg(feature = "profiles")]
    if config.profiles_enabled {
        // Collect profile manifest
        let manifest = config.config_dir.join(MANIFEST_FILE);
        if manifest.exists() {
            files.push((manifest, PathBuf::from(MANIFEST_FILE)));
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
        return Ok(files);
    }

    // Non-profiled or feature disabled: just the single settings file
    #[cfg(not(feature = "profiles"))]
    let settings_path = config.settings_path();
    #[cfg(feature = "profiles")]
    let settings_path = config.settings_path();

    if settings_path.exists() {
        files.push((settings_path, PathBuf::from(&config.settings_file)));
    }

    Ok(files)
}

/// Backup manager for creating and analyzing backups
pub struct BackupManager<'a, S: StorageBackend + 'static> {
    /// Reference to the settings manager
    pub(crate) manager: &'a SettingsManager<S>,
}

impl<'a, S: StorageBackend + 'static> BackupManager<'a, S> {
    /// Create a new backup manager
    pub fn new(manager: &'a SettingsManager<S>) -> Self {
        Self { manager }
    }

    /// Register an external config provider
    pub fn register_external_provider(&self, provider: Box<dyn ExternalConfigProvider>) {
        self.manager.register_external_provider(provider);
    }

    /// Create a backup
    pub fn create(&self, options: BackupOptions) -> Result<PathBuf> {
        info!("📦 Creating backup with options: {:?}", options.export_type);

        // Validate password if provided (clone to avoid moving from options)
        let password = validate_password(options.password.clone())?;

        // Create temp directory for gathering files
        let temp_dir = tempfile::tempdir().map_err(|e| Error::BackupFailed(e.to_string()))?;
        let export_dir = temp_dir.path().join("export");
        fs::create_dir_all(&export_dir).map_err(|e| Error::DirectoryCreate {
            path: export_dir.display().to_string(),
            source: e,
        })?;

        // Gather files to backup
        let (contents, total_size) = self.gather_files(&export_dir, &options)?;

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
                created_at: Utc::now(),
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

        let manifest_json = serde_json::to_string_pretty(&manifest)
            .map_err(|e| Error::BackupFailed(e.to_string()))?;

        // Generate output filename
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
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
            path: options.output_dir.display().to_string(),
            source: e,
        })?;

        // Create final .rcman container
        create_rcman_container(
            &output_path,
            &manifest_json,
            &inner_archive_path,
            data_filename,
        )?;

        info!("✅ Backup created: {:?}", output_path);
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
        // Includes settings if:
        // - explicitly requested (options.include_settings)
        // - OR it's a Full export (unless explicitly disabled, but ExportType::Full typically implies everything)
        // - AND it's not a Single export (which is exclusive)
        let include_settings = (options.include_settings
            || matches!(options.export_type, ExportType::Full))
            && !matches!(options.export_type, ExportType::Single { .. });

        if include_settings {
            for (src, dest) in collect_settings_files(self.manager.config(), options)? {
                let full_dest = export_dir.join(&dest);
                if let Some(parent) = full_dest.parent() {
                    fs::create_dir_all(parent).map_err(|e| Error::DirectoryCreate {
                        path: parent.display().to_string(),
                        source: e,
                    })?;
                }
                fs::copy(&src, &full_dest).map_err(|e| Error::FileRead {
                    path: src.display().to_string(),
                    source: e,
                })?;
                total_size += fs::metadata(&full_dest).map(|m| m.len()).unwrap_or(0);
                contents.file_count += 1;
                debug!("📄 Added settings file: {}", dest.display());
            }
            contents.settings = true;
        }

        // 2. Sub-settings
        let sub_settings_to_backup = match &options.export_type {
            // For Full OR SettingsOnly, we respect the include_sub_settings list
            // This allows creating "partial" backups (e.g. settings=false, sub_settings=["backend"])
            ExportType::Full | ExportType::SettingsOnly => options.include_sub_settings.clone(),
            ExportType::Single {
                settings_type,
                name,
            } => {
                // Handle single entry export
                if let Ok(sub) = self.manager.sub_settings(settings_type) {
                    let sub_export_dir = export_dir.join(settings_type);
                    fs::create_dir_all(&sub_export_dir).map_err(|e| Error::DirectoryCreate {
                        path: sub_export_dir.display().to_string(),
                        source: e,
                    })?;

                    let value = sub.get_value(name)?;
                    let dest = sub_export_dir.join(format!("{}.json", name));
                    let json = serde_json::to_string_pretty(&value)?;
                    fs::write(&dest, &json).map_err(|e| Error::FileWrite {
                        path: dest.display().to_string(),
                        source: e,
                    })?;
                    total_size += json.len() as u64;
                    contents.file_count += 1;
                    contents.sub_settings.insert(
                        settings_type.clone(),
                        SubSettingsManifestEntry::MultiFile(vec![name.to_string()]),
                    );
                    debug!("📄 Added single entry: {}/{}", settings_type, name);
                }
                Vec::new() // Don't process further
            }
        };

        for sub_type in sub_settings_to_backup {
            #[cfg(feature = "profiles")]
            let sub_export_dir = export_dir.join(&sub_type);

            if let Ok(sub) = self.manager.sub_settings(&sub_type) {
                // Check for profiles
                #[cfg(feature = "profiles")]
                let profiles_enabled = sub.profiles_enabled();
                #[cfg(not(feature = "profiles"))]
                let profiles_enabled = false;

                if profiles_enabled {
                    #[cfg(feature = "profiles")]
                    {
                        // Copy .profiles.json
                        let root_path = sub.root_path();
                        let profiles_manifest = root_path.join(MANIFEST_FILE);
                        if profiles_manifest.exists() {
                            let dest = sub_export_dir.join(MANIFEST_FILE);
                            // Ensure sub_export_dir exists (we might not have created it yet)
                            fs::create_dir_all(&sub_export_dir).map_err(|e| {
                                Error::DirectoryCreate {
                                    path: sub_export_dir.display().to_string(),
                                    source: e,
                                }
                            })?;

                            fs::copy(&profiles_manifest, &dest).map_err(|e| Error::FileRead {
                                path: profiles_manifest.display().to_string(),
                                source: e,
                            })?;
                            total_size += fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
                            contents.file_count += 1;
                        }

                        // Handle profiles folder
                        let profiles_dir = root_path.join(PROFILES_DIR);
                        if profiles_dir.exists() {
                            let dest_profiles_dir = sub_export_dir.join(PROFILES_DIR);
                            fs::create_dir_all(&dest_profiles_dir).map_err(|e| {
                                Error::DirectoryCreate {
                                    path: dest_profiles_dir.display().to_string(),
                                    source: e,
                                }
                            })?;

                            let mut profile_names = Vec::new();

                            for entry in
                                fs::read_dir(&profiles_dir).map_err(|e| Error::DirectoryRead {
                                    path: profiles_dir.display().to_string(),
                                    source: e,
                                })?
                            {
                                let entry = entry.map_err(|e| Error::DirectoryRead {
                                    path: profiles_dir.display().to_string(),
                                    source: e,
                                })?;

                                let profile_name = entry.file_name().to_string_lossy().to_string();

                                // Filter
                                if !options.include_profiles.is_empty()
                                    && !options.include_profiles.contains(&profile_name)
                                {
                                    continue;
                                }

                                let profile_path = entry.path();
                                let profile_export_dir = dest_profiles_dir.join(&profile_name);
                                fs::create_dir_all(&profile_export_dir).map_err(|e| {
                                    Error::DirectoryCreate {
                                        path: profile_export_dir.display().to_string(),
                                        source: e,
                                    }
                                })?;

                                // Copy all JSON files from this profile
                                if let Ok(profile_entries) = fs::read_dir(&profile_path) {
                                    for item_entry in profile_entries.flatten() {
                                        let path = item_entry.path();
                                        if path.extension().and_then(|s| s.to_str()) == Some("json")
                                        {
                                            let dest =
                                                profile_export_dir.join(item_entry.file_name());
                                            fs::copy(&path, &dest).map_err(|e| {
                                                Error::FileRead {
                                                    path: path.display().to_string(),
                                                    source: e,
                                                }
                                            })?;
                                            total_size +=
                                                fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
                                            contents.file_count += 1;
                                        }
                                    }
                                    profile_names.push(profile_name);
                                }
                            }

                            if !profile_names.is_empty() {
                                contents.sub_settings.insert(
                                    sub_type.clone(),
                                    SubSettingsManifestEntry::Profiled {
                                        profiles: profile_names,
                                        single_file: sub.is_single_file(),
                                    },
                                );
                            }
                        }
                    }
                } else {
                    let sub_export_dir = export_dir.join(&sub_type);

                    // Handle single-file mode differently
                    if sub.is_single_file() {
                        // In single-file mode, we just copy the single file as {sub_type}.json
                        // But we still list items in the manifest for granular restore awareness
                        if let Some(path) = sub.file_path() {
                            if path.exists() {
                                let dest = sub_export_dir.join(format!("{}.json", sub_type));
                                // Ensure dir
                                fs::create_dir_all(&sub_export_dir).map_err(|e| {
                                    Error::DirectoryCreate {
                                        path: sub_export_dir.display().to_string(),
                                        source: e,
                                    }
                                })?;

                                fs::copy(&path, &dest).map_err(|e| Error::FileRead {
                                    path: path.display().to_string(),
                                    source: e,
                                })?;
                                total_size += fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
                                contents.file_count += 1;

                                // For single-file mode, we use SingleFile manifest entry with filename
                                contents.sub_settings.insert(
                                    sub_type.clone(),
                                    SubSettingsManifestEntry::SingleFile(format!(
                                        "{}.json",
                                        sub_type
                                    )),
                                );
                                debug!("📄 Added single-file sub-settings: {}", sub_type);
                            }
                        }
                    } else {
                        // Multi-file mode: create directory and copy individuals
                        fs::create_dir_all(&sub_export_dir).map_err(|e| {
                            Error::DirectoryCreate {
                                path: sub_export_dir.display().to_string(),
                                source: e,
                            }
                        })?;

                        let mut items = Vec::new();

                        for name in sub.list()? {
                            if let Ok(value) = sub.get_value(&name) {
                                let dest = sub_export_dir.join(format!("{}.json", name));
                                let json = serde_json::to_string_pretty(&value)?;
                                fs::write(&dest, &json).map_err(|e| Error::FileWrite {
                                    path: dest.display().to_string(),
                                    source: e,
                                })?;
                                total_size += json.len() as u64;
                                contents.file_count += 1;
                                items.push(name);
                            }
                        }

                        contents
                            .sub_settings
                            .insert(sub_type.clone(), SubSettingsManifestEntry::MultiFile(items));
                        debug!("📄 Added sub-settings directory: {}", sub_type);
                    }
                }
            }
        }

        // 3. External configs
        if !options.include_external_configs.is_empty() {
            let providers = self.manager.external_providers.read();
            let mut all_configs = Vec::new();

            // Add static configs from settings
            all_configs.extend(self.manager.config().external_configs.clone());

            // Add dynamic configs from providers
            for provider in providers.iter() {
                all_configs.extend(provider.get_configs());
            }

            // Using explicit variable type to help inference if needed
            // (all_configs is Vec<ExternalConfig>)

            let external_dir = export_dir.join("external");

            for config in all_configs {
                if !options.include_external_configs.contains(&config.id) {
                    continue;
                }

                if !config.exists() {
                    debug!("⏭️ Skipping non-existent external config: {}", config.id);
                    continue;
                }

                fs::create_dir_all(&external_dir).map_err(|e| Error::DirectoryCreate {
                    path: external_dir.display().to_string(),
                    source: e,
                })?;

                let dest = external_dir.join(&config.archive_filename);

                // Handle different export sources
                match &config.export_source {
                    super::types::ExportSource::File(path) => {
                        fs::copy(path, &dest).map_err(|e| Error::FileRead {
                            path: path.display().to_string(),
                            source: e,
                        })?;
                    }
                    super::types::ExportSource::Command { program, args } => {
                        let output = std::process::Command::new(program)
                            .args(args)
                            .output()
                            .map_err(|e| {
                                Error::BackupFailed(format!(
                                    "Failed to run command '{}': {}",
                                    program, e
                                ))
                            })?;

                        if !output.status.success() {
                            return Err(Error::BackupFailed(format!(
                                "Command '{}' failed with exit code {:?}",
                                program,
                                output.status.code()
                            )));
                        }

                        fs::write(&dest, &output.stdout).map_err(|e| Error::FileWrite {
                            path: dest.display().to_string(),
                            source: e,
                        })?;
                    }
                    super::types::ExportSource::Content(bytes) => {
                        fs::write(&dest, bytes).map_err(|e| Error::FileWrite {
                            path: dest.display().to_string(),
                            source: e,
                        })?;
                    }
                }

                total_size += fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
                contents.file_count += 1;
                contents.external_configs.push(config.id.clone());
                debug!("📄 Added external config: {}", config.id);
            }
        }

        Ok((contents, total_size))
    }

    /// Analyze a backup file
    pub fn analyze(&self, path: &Path) -> Result<BackupAnalysis> {
        if !path.exists() {
            return Err(Error::PathNotFound(path.display().to_string()));
        }

        // Read manifest from the .rcman file
        let manifest_bytes = super::archive::read_file_from_zip(path, "manifest.json")?;
        let manifest_str = String::from_utf8(manifest_bytes)
            .map_err(|e| Error::InvalidBackup(format!("Invalid manifest encoding: {}", e)))?;

        let manifest: BackupManifest = serde_json::from_str(&manifest_str)
            .map_err(|e| Error::InvalidBackup(format!("Invalid manifest JSON: {}", e)))?;

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
            path: data_archive_path.display().to_string(),
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

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SettingsConfig;
    use crate::storage::JsonStorage;
    use crate::sub_settings::SubSettingsConfig;
    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn test_create_full_backup() {
        let temp = tempdir().unwrap();
        let config = SettingsConfig {
            config_dir: temp.path().to_path_buf(),
            settings_file: "settings.json".into(),
            app_name: "test-app".into(),
            app_version: "1.0.0".into(),
            storage: JsonStorage::new(),
            enable_credentials: false,
            external_configs: Vec::new(),
            env_prefix: None,
            env_overrides_secrets: false,
            migrator: None,
            #[cfg(feature = "profiles")]
            profiles_enabled: false,
            #[cfg(feature = "profiles")]
            profile_migrator: crate::profiles::ProfileMigrator::None,
        };

        let manager = SettingsManager::new(config).unwrap();

        // Create some settings
        fs::write(
            temp.path().join("settings.json"),
            r#"{"general": {"theme": "dark"}}"#,
        )
        .unwrap();

        // Register and populate sub-settings
        manager.register_sub_settings(SubSettingsConfig::new("profiles"));
        let profiles = manager.sub_settings("profiles").unwrap();
        profiles
            .set("default", &json!({"name": "Default"}))
            .unwrap();

        // Create backup
        let backup_dir = temp.path().join("backups");
        let backup = manager.backup();
        let backup_path = backup
            .create(BackupOptions {
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
        let config = SettingsConfig {
            config_dir: temp.path().to_path_buf(),
            settings_file: "settings.json".into(),
            app_name: "test-app".into(),
            app_version: "1.0.0".into(),
            storage: JsonStorage::new(),
            enable_credentials: false,
            external_configs: Vec::new(),
            env_prefix: None,
            env_overrides_secrets: false,
            migrator: None,
            #[cfg(feature = "profiles")]
            profiles_enabled: false,
            #[cfg(feature = "profiles")]
            profile_migrator: crate::profiles::ProfileMigrator::None,
        };

        let manager = SettingsManager::new(config).unwrap();

        // Create minimal backup
        fs::write(temp.path().join("settings.json"), "{}").unwrap();

        let backup = manager.backup();
        let backup_path = backup
            .create(BackupOptions {
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
        let config = SettingsConfig {
            config_dir: temp.path().to_path_buf(),
            settings_file: "settings.json".into(),
            app_name: "test-app".into(),
            app_version: "1.0.0".into(),
            storage: JsonStorage::new(),
            enable_credentials: false,
            external_configs: Vec::new(),
            env_prefix: None,
            env_overrides_secrets: false,
            migrator: None,
            #[cfg(feature = "profiles")]
            profiles_enabled: false,
            #[cfg(feature = "profiles")]
            profile_migrator: crate::profiles::ProfileMigrator::None,
        };

        let manager = SettingsManager::new(config).unwrap();

        // Create settings
        fs::write(
            temp.path().join("settings.json"),
            r#"{"general": {"theme": "dark"}}"#,
        )
        .unwrap();

        // Register and populate sub-settings
        manager.register_sub_settings(SubSettingsConfig::new("profiles"));
        let profiles = manager.sub_settings("profiles").unwrap();
        profiles
            .set("default", &json!({"name": "Default"}))
            .unwrap();

        // Create PARTIAL backup: No settings, only profiles
        let backup_dir = temp.path().join("backups");
        let backup = manager.backup();
        let backup_path = backup
            .create(BackupOptions {
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
