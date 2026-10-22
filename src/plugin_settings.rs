use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{IoContext, Result, ScannerError};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginSettings {
    pub schema_version: u32,
    pub enabled: bool,
    pub hooks: Hooks,
    /// `cursor` is optional and omitted while empty, so plugin bundles released before
    /// Cursor support keep accepting settings this version writes.
    pub disabled_chats: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hooks {
    pub user_input: bool,
    pub tool_result: bool,
    pub mcp_result: bool,
    /// Pre-execution shell command check. Optional and omitted while on, so plugin bundles
    /// released before it keep accepting settings this version writes.
    #[serde(default = "enabled", skip_serializing_if = "is_enabled")]
    pub shell_command: bool,
}

fn enabled() -> bool {
    true
}

fn is_enabled(value: &bool) -> bool {
    *value
}

impl Default for PluginSettings {
    fn default() -> Self {
        Self {
            schema_version: 1,
            enabled: true,
            hooks: Hooks {
                user_input: true,
                tool_result: true,
                mcp_result: true,
                shell_command: true,
            },
            disabled_chats: ["codex", "claude", "deepseek"]
                .into_iter()
                .map(|host| (host.into(), vec![]))
                .collect(),
        }
    }
}

impl PluginSettings {
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default())
            }
            Ok(info)
                if info.is_file() && !info.file_type().is_symlink() && info.len() <= 256 * 1024 => {
            }
            _ => return Err(invalid("unsafe plugin settings file")),
        }
        let settings: Self = serde_json::from_slice(&std::fs::read(path).at(path)?)
            .map_err(|_| invalid("invalid plugins.json"))?;
        settings.validate()?;
        Ok(settings)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || ["codex", "claude", "deepseek"]
                .iter()
                .any(|host| !self.disabled_chats.contains_key(*host))
            || self
                .disabled_chats
                .keys()
                .any(|host| !["codex", "claude", "deepseek", "cursor"].contains(&host.as_str()))
            || self
                .disabled_chats
                .values()
                .any(|ids| ids.len() > 1000 || ids.iter().any(|id| !valid_chat(id)))
        {
            return Err(invalid("invalid plugin settings or chat ID"));
        }
        Ok(())
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let parent = path
            .parent()
            .ok_or_else(|| invalid("settings need a parent directory"))?;
        crate::dashboard::ensure_directory(parent)?;
        let staging = parent.join(format!(".plugins-{:032x}.tmp", rand::random::<u128>()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let result = (|| {
            let mut file = options.open(&staging).at(&staging)?;
            let mut stored = self.clone();
            if stored
                .disabled_chats
                .get("cursor")
                .is_some_and(Vec::is_empty)
            {
                stored.disabled_chats.remove("cursor");
            }
            let bytes =
                serde_json::to_vec_pretty(&stored).map_err(|_| invalid("invalid settings"))?;
            file.write_all(&bytes).at(&staging)?;
            file.sync_all().at(&staging)?;
            crate::atomic_file::replace(&staging, path).at(path)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(staging);
        }
        result
    }
}

pub fn valid_chat(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 256
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}

fn invalid(message: &str) -> ScannerError {
    ScannerError::Config {
        source_name: "plugin settings".into(),
        message: message.into(),
    }
}

pub fn execute(command: crate::cli::PluginCommand) -> Result<()> {
    use crate::cli::PluginCommand;
    let path = std::env::var_os("PATRONUS_PLUGIN_SETTINGS")
        .map(std::path::PathBuf::from)
        .unwrap_or(crate::config::user_root()?.join("plugins.json"));
    if !path.is_absolute() {
        return Err(invalid("plugin settings path must be absolute"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("settings need a parent directory"))?;
    crate::dashboard::ensure_directory(parent)?;
    let lock_path = parent.join(".plugins.lock");
    if std::fs::symlink_metadata(&lock_path)
        .is_ok_and(|info| !info.is_file() || info.file_type().is_symlink())
    {
        return Err(invalid("unsafe plugin settings lock"));
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(&lock_path).at(&lock_path)?;
    fs2::FileExt::lock_exclusive(&lock).at(&lock_path)?;
    let mut settings = PluginSettings::load(&path)?;
    match command {
        PluginCommand::Show => {
            println!(
                "{}",
                serde_json::to_string_pretty(&settings).map_err(|_| invalid("invalid settings"))?
            );
            return Ok(());
        }
        PluginCommand::Init => {
            if path.exists() {
                return Err(invalid(
                    "plugins.json already exists; edit it or use plugins hook/pause/resume",
                ));
            }
        }
        PluginCommand::Hook { surface, enabled } => match surface.as_str() {
            "user_input" => settings.hooks.user_input = enabled,
            "tool_result" => settings.hooks.tool_result = enabled,
            "mcp_result" => settings.hooks.mcp_result = enabled,
            "shell_command" => settings.hooks.shell_command = enabled,
            _ => return Err(invalid("unknown hook")),
        },
        PluginCommand::Pause { host, chat } => {
            if !valid_chat(&chat) {
                return Err(invalid("invalid chat ID"));
            }
            let ids = if host == "cursor" {
                settings.disabled_chats.entry(host).or_default()
            } else {
                settings
                    .disabled_chats
                    .get_mut(&host)
                    .ok_or_else(|| invalid("unknown host"))?
            };
            if !ids.contains(&chat) {
                ids.push(chat);
            }
        }
        PluginCommand::Resume { host, chat } => {
            if !valid_chat(&chat) {
                return Err(invalid("invalid chat ID"));
            }
            if let Some(ids) = settings.disabled_chats.get_mut(&host) {
                ids.retain(|id| id != &chat);
            } else if host != "cursor" {
                return Err(invalid("unknown host"));
            }
        }
    }
    settings.write(&path)?;
    println!("Updated {}", path.display());
    Ok(())
}
