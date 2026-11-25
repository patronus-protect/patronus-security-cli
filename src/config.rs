use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

use crate::cli::{ProgressMode, ScanOptions};
use crate::error::{IoContext, Result, ScannerError};

pub const DEFAULTS: &str = include_str!("../config/defaults.toml");

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub plugin_policies: std::collections::BTreeMap<String, crate::plugin_policies::Profile>,
    #[serde(default)]
    pub shell: crate::scanning::shell_config::ShellSettings,
    pub schema_version: u32,
    pub provider: ProviderConfig,
    pub scan: ScanConfig,
    pub ignore: IgnoreConfig,
    pub chunking: ChunkingConfig,
    pub ark: ArkConfig,
    #[serde(default)]
    pub analysis: crate::analysis_config::AnalysisConfig,
    pub progress: ProgressConfig,
    pub output: OutputConfig,
    pub support: SupportConfig,
    #[serde(default)]
    pub runtime: crate::runtime::config::RuntimeConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    pub mode: ProviderMode,
    pub api_base_url: String,
    pub api_key_env: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum ProviderMode {
    Local,
    Api,
    Hybrid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanConfig {
    pub respect_gitignore: bool,
    pub respect_ignore_files: bool,
    pub include_hidden: bool,
    pub follow_symlinks: bool,
    pub max_file_bytes: u64,
    pub supported_encodings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IgnoreConfig {
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChunkingConfig {
    pub target_bytes: usize,
    pub overlap_bytes: usize,
    pub prefer_line_boundaries: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArkConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_dir: Option<PathBuf>,
    pub categories: Vec<String>,
    pub max_level: String,
    pub download_files: bool,
    pub queue_capacity: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgressConfig {
    pub mode: ProgressMode,
    pub plain_interval_seconds: u64,
    pub eta_min_seconds: u64,
    pub eta_min_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputConfig {
    pub root: PathBuf,
    pub include_chunk_content: bool,
    pub include_evidence_text: bool,
    pub write_progress_events: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportConfig {
    pub endpoint: String,
    pub default_artifacts: Vec<String>,
    pub max_bundle_bytes: u64,
}

impl Config {
    pub fn load(explicit: Option<&Path>, repo_root: Option<&Path>) -> Result<Self> {
        let mut merged = parse_value(DEFAULTS, "compiled defaults")?;
        if let Some(project) = ProjectDirs::from("com", "Patronus", "patronus-security-scanner") {
            let user = project.config_dir().join("config.toml");
            if user.is_file() {
                merge_file(&mut merged, &user)?;
            }
        }
        let user = user_root()?.join("config.toml");
        if user.is_file() {
            merge_file(&mut merged, &user)?;
        }
        if let Some(root) = repo_root {
            let repo = root.join(".patronus-security-scanner.toml");
            if repo.is_file() {
                merge_file(&mut merged, &repo)?;
            }
        }
        if let Some(path) = explicit {
            merge_file(&mut merged, path)?;
        }
        // Retire the unused legacy origin without changing the selected provider.
        if let Some(provider) = merged
            .get_mut("provider")
            .and_then(toml::Value::as_table_mut)
        {
            provider.remove("webmcp_origin");
        }
        let mut config: Config = merged.try_into().map_err(|error| ScannerError::Config {
            source_name: "merged configuration".into(),
            message: error.to_string(),
        })?;
        // Also normalize the old compiled default in existing user config files.
        if matches!(
            config.output.root.to_str(),
            Some("~/.patronus-security-scanner/output" | ".patronus-security-scanner/output")
        ) {
            config.output.root = user_root()?.join("output");
        }
        for profile in config.plugin_policies.values_mut() {
            profile.add_missing_rules();
        }
        config.validate()?;
        Ok(config)
    }

    pub fn apply_scan_options(&mut self, options: &ScanOptions) -> Result<()> {
        self.ignore.patterns.extend(options.ignore.iter().cloned());
        if options.activate_store_content {
            self.output.include_chunk_content = true;
        }
        if !options.category.is_empty() {
            self.ark.categories.clone_from(&options.category);
        }
        if let Some(level) = options.max_level {
            self.ark.max_level = level.as_str().into();
        }
        if let Some(mode) = options.progress {
            self.progress.mode = mode;
        }
        if options.quiet {
            self.progress.mode = ProgressMode::Off;
        }
        if let Some(root) = &options.output {
            self.output.root = root.clone();
        }
        self.validate()
    }

    pub fn validate(&self) -> Result<()> {
        let invalid = |message: String| ScannerError::Config {
            source_name: "effective configuration".into(),
            message,
        };
        self.runtime.validate().map_err(invalid)?;
        self.shell
            .validate(crate::shell_check::model_directory(self.ark.model_dir.as_deref()).as_deref())
            .map_err(invalid)?;
        self.analysis.validate(&self.ark).map_err(invalid)?;
        for (scope, profile) in &self.plugin_policies {
            if !crate::plugin_policies::valid_scope(scope) {
                return Err(invalid("Unknown plugin policy scope".into()));
            }
            profile.validate().map_err(invalid)?;
        }
        if self
            .ark
            .model_dir
            .as_ref()
            .is_some_and(|p| !p.is_absolute())
        {
            return Err(invalid("ark.model_dir must be absolute".into()));
        }
        if self.ark.categories.is_empty() {
            return Err(invalid("ark.categories must not be empty".into()));
        }
        if self.schema_version != 1 {
            return Err(invalid(format!(
                "unsupported schema_version {}; expected 1",
                self.schema_version
            )));
        }
        if self.provider.api_key_env.trim().is_empty() {
            return Err(invalid("provider.api_key_env must not be empty".into()));
        }
        if self.provider.api_base_url != "https://control.patronus.studio/api/v1" {
            return Err(invalid(
                "API requests require https://control.patronus.studio/api/v1".into(),
            ));
        }
        if self.chunking.target_bytes == 0
            || self.chunking.overlap_bytes >= self.chunking.target_bytes
        {
            return Err(invalid(
                "chunking.target_bytes must be positive and overlap_bytes must be smaller".into(),
            ));
        }
        if self.scan.max_file_bytes == 0 || self.ark.queue_capacity == 0 {
            return Err(invalid(
                "scan.max_file_bytes and ark.queue_capacity must be positive".into(),
            ));
        }
        if self.scan.supported_encodings.is_empty()
            || self.scan.supported_encodings.iter().any(|encoding| {
                !matches!(encoding.as_str(), "utf-8" | "utf-16le-bom" | "utf-16be-bom")
            })
        {
            return Err(invalid(
                "scan.supported_encodings must contain only supported non-empty encoding names"
                    .into(),
            ));
        }
        if !matches!(self.ark.max_level.as_str(), "l1" | "l2" | "l3") {
            return Err(invalid(format!(
                "ark.max_level must be l1, l2, or l3; got {}",
                self.ark.max_level
            )));
        }
        for category in &self.ark.categories {
            ark_categories(category).map_err(invalid)?;
        }
        Ok(())
    }

    pub fn redacted_toml(&self) -> Result<String> {
        let mut value =
            toml::Value::try_from(self).map_err(|error| ScannerError::Output(error.to_string()))?;
        redact_value(&mut value);
        toml::to_string_pretty(&value).map_err(|error| ScannerError::Output(error.to_string()))
    }
}

pub fn user_root() -> Result<PathBuf> {
    if let Some(root) = std::env::var_os("PATRONUS_DATA_DIR") {
        let root = PathBuf::from(root);
        if !root.is_absolute() {
            return Err(ScannerError::Output(
                "PATRONUS_DATA_DIR must be absolute".into(),
            ));
        }
        return Ok(root);
    }
    directories::BaseDirs::new()
        .map(|dirs| dirs.home_dir().join(".patronus-security-scanner"))
        .ok_or_else(|| ScannerError::Output("cannot resolve the user home directory".into()))
}

/// Ark classes behind one of our scan categories.
///
/// Ark 0.1.18 split its old `injection`, `dlp` and `threat` categories into
/// attack classes. Each of our categories keeps the detections it had on Ark
/// 0.1.16 by requesting the classes its rules and model labels now report
/// under; the results are merged back into our category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArkClasses {
    /// Scanned up to the category's configured level.
    pub primary: &'static [patronus_ark_core::SecurityCategory],
    /// Scanned with L1 rules only. Their old rules reported under this category,
    /// but Ark 0.1.18 runs the threat model (formerly the opt-in `threat`
    /// category) for `unsafe_action` at L2/L3.
    pub l1_only: &'static [patronus_ark_core::SecurityCategory],
}

pub fn ark_categories(value: &str) -> std::result::Result<ArkClasses, String> {
    use patronus_ark_core::SecurityCategory as Ark;
    match value {
        // Rules that reported under `injection` before 0.1.18; see Ark's
        // detectors/injection/rules/rule_categories.json.
        "prompt_injection" | "injection" => Ok(ArkClasses {
            primary: &[
                Ark::Injection,
                Ark::Jailbreak,
                Ark::PromptExtraction,
                Ark::ToolPoisoning,
            ],
            l1_only: &[
                Ark::Exfiltration,
                Ark::UnsafeAction,
                Ark::MemoryPoisoning,
                Ark::AgentConfigTampering,
            ],
        }),
        // Secret transfers moved to `exfiltration`; destructive operations,
        // sensitive material and risky MCP calls to `unsafe_action`.
        "dlp" => Ok(ArkClasses {
            primary: &[Ark::Dlp],
            l1_only: &[Ark::Exfiltration, Ark::UnsafeAction],
        }),
        "pii" => Ok(ArkClasses {
            primary: &[Ark::Pii],
            l1_only: &[],
        }),
        // The old threat model now runs under `unsafe_action`; its labels report
        // under these classes. Its instruction-override label goes to
        // `injection`, which `prompt_injection` scans with Wolf already.
        "threat" => Ok(ArkClasses {
            primary: &[
                Ark::UnsafeAction,
                Ark::HarmfulContent,
                Ark::Exfiltration,
                Ark::ToxicLanguage,
            ],
            l1_only: &[],
        }),
        other => Err(format!("unsupported Ark category {other:?}")),
    }
}

fn parse_value(text: &str, source_name: &str) -> Result<toml::Value> {
    toml::from_str(text).map_err(|error| ScannerError::Config {
        source_name: source_name.into(),
        message: error.to_string(),
    })
}

fn merge_file(base: &mut toml::Value, path: &Path) -> Result<()> {
    let text = std::fs::read_to_string(path).at(path)?;
    let overlay = parse_value(&text, &path.display().to_string())?;
    merge(base, overlay);
    Ok(())
}

fn merge(base: &mut toml::Value, overlay: toml::Value) {
    match (base, overlay) {
        (toml::Value::Table(base), toml::Value::Table(overlay)) => {
            for (key, value) in overlay {
                if let Some(existing) = base.get_mut(&key) {
                    merge(existing, value);
                } else {
                    base.insert(key, value);
                }
            }
        }
        (base, overlay) => *base = overlay,
    }
}

fn redact_value(value: &mut toml::Value) {
    if let toml::Value::Table(table) = value {
        for (key, value) in table {
            if key != "api_key_env"
                && value.is_str()
                && ["token", "secret", "password", "credential", "api_key"]
                    .iter()
                    .any(|needle| key.to_ascii_lowercase().contains(needle))
            {
                *value = toml::Value::String("<redacted>".into());
            } else {
                redact_value(value);
            }
        }
    }
}

pub fn write_defaults(path: &Path, force: bool, provider: Option<ProviderMode>) -> Result<()> {
    if path.exists() && !force {
        return Err(ScannerError::Config {
            source_name: path.display().to_string(),
            message: "file exists; use --force to replace it".into(),
        });
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).at(parent)?;
    }
    let mut config: Config = toml::from_str(DEFAULTS).map_err(|error| ScannerError::Config {
        source_name: "compiled defaults".into(),
        message: error.to_string(),
    })?;
    if let Some(provider) = provider {
        config.provider.mode = provider;
    }
    let text =
        toml::to_string_pretty(&config).map_err(|error| ScannerError::Output(error.to_string()))?;
    std::fs::write(path, text).at(path)
}
