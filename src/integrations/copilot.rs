//! GitHub Copilot CLI lifecycle. Copilot loads every `*.json` file in the user's hooks directory,
//! so Patronus owns one file there (`hooks/patronus-security.json`) and switches it with
//! `disableAllHooks`, which skips only that file. The MCP server is one entry in the user-level
//! `mcp-config.json`; every other entry is kept unchanged. The hook runtime is a verified copy of
//! the released Copilot plugin under the Patronus data directory.
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::{atomic_write, discover_root, IntegrationStatus, StatusObservation};
use crate::cli::{IntegrationAction, IntegrationArgs, IntegrationHost, IntegrationScope};
use crate::error::{Result, ScannerError};

/// Copilot events Patronus registers, with their hook timeouts in seconds. `postToolUse` also
/// answers Patronus' own tools, static audits included.
const EVENTS: [(&str, u64); 5] = [
    ("userPromptTransformed", 90),
    ("preToolUse", 60),
    ("postToolUse", 330),
    ("postToolUseFailure", 90),
    ("sessionEnd", 30),
];
const MANIFEST: &str = "plugin.json";
const HOOKS: &str = "hooks/hooks.json";
const RUNTIME: &str = "scripts/patronus.mjs";
const HOOK_FILE: &str = "patronus-security.json";
const MCP_SERVER: &str = "patronus";
/// Every Patronus hook command contains this marker.
const MARKER: &str = "/scripts/patronus.mjs\" hook copilot ";

pub(super) fn execute(args: IntegrationArgs) -> Result<()> {
    if args.scope != IntegrationScope::User {
        return Err(integration("Copilot lifecycle supports only --scope user"));
    }
    let config = config_dir()?;
    let root = install_root()?;
    match args.action {
        IntegrationAction::Install => {
            let source = plugin_source(args.source.as_deref())?;
            copy_plugin(&source, &root)?;
            set_mcp(&config, Some(&root))?;
            set_hooks(&config, Some((&root, true)))
        }
        IntegrationAction::Update => {
            let enabled = read_state(&config, &root).enabled == Some(true);
            let source = plugin_source(args.source.as_deref())?;
            copy_plugin(&source, &root)?;
            set_mcp(&config, Some(&root))?;
            set_hooks(&config, Some((&root, enabled)))
        }
        IntegrationAction::Enable => {
            if !root.join(RUNTIME).is_file() {
                return Err(integration(
                    "the Patronus Copilot plugin is not installed; run integration copilot install",
                ));
            }
            set_mcp(&config, Some(&root))?;
            set_hooks(&config, Some((&root, true)))
        }
        IntegrationAction::Disable => {
            if !root.join(RUNTIME).is_file() {
                return set_hooks(&config, None);
            }
            set_hooks(&config, Some((&root, false)))
        }
        IntegrationAction::Uninstall => {
            set_hooks(&config, None)?;
            set_mcp(&config, None)?;
            match std::fs::remove_dir_all(&root) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(integration(
                    format!("could not remove {}: {error}", root.display()),
                )),
                _ => Ok(()),
            }
        }
        IntegrationAction::Status { format } => status(&config, &root).print(format),
    }
}

pub(super) fn dashboard_status() -> Result<IntegrationStatus> {
    Ok(status(&config_dir()?, &install_root()?))
}

/// Mirrors Copilot's own lookup: `COPILOT_HOME`, then `~/.copilot`.
fn config_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("COPILOT_HOME").filter(|dir| !dir.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    directories::BaseDirs::new()
        .map(|dirs| dirs.home_dir().join(".copilot"))
        .ok_or_else(|| integration("cannot resolve the user home directory"))
}

fn install_root() -> Result<PathBuf> {
    Ok(crate::config::user_root()?
        .join("integrations")
        .join("copilot"))
}

fn is_plugin(dir: &Path) -> bool {
    dir.join(MANIFEST).is_file() && dir.join(HOOKS).is_file() && dir.join(RUNTIME).is_file()
}

fn plugin_source(explicit: Option<&Path>) -> Result<PathBuf> {
    let source = match explicit {
        Some(path) => path.to_path_buf(),
        None => {
            let cwd = std::env::current_dir().map_err(|error| integration(error.to_string()))?;
            discover_root(&cwd, Path::new("plugins/copilot/plugin.json")).ok_or_else(|| {
                integration("could not find plugins/copilot; pass --source <plugin-root>")
            })?
        }
    };
    // A release archive or a repository checkout holds the plugin under plugins/copilot.
    let source = if is_plugin(&source) {
        source
    } else {
        source.join("plugins").join("copilot")
    };
    if !is_plugin(&source) {
        return Err(integration(format!(
            "{} does not contain the Copilot plugin ({MANIFEST}, {HOOKS} and {RUNTIME})",
            source.display()
        )));
    }
    Ok(source)
}

/// Copies the plugin through a staging directory so a failed copy never leaves a partial runtime.
fn copy_plugin(source: &Path, root: &Path) -> Result<()> {
    let parent = root
        .parent()
        .ok_or_else(|| integration("invalid install root"))?;
    crate::dashboard::ensure_directory(parent)?;
    let staging = parent.join(format!(".copilot-{:016x}", rand::random::<u64>()));
    let result = (|| {
        copy_tree(source, &staging)?;
        let previous = parent.join(format!(".copilot-old-{:016x}", rand::random::<u64>()));
        let had_previous = root.exists();
        if had_previous {
            std::fs::rename(root, &previous).map_err(|error| integration(error.to_string()))?;
        }
        if let Err(error) = std::fs::rename(&staging, root) {
            if had_previous {
                let _ = std::fs::rename(&previous, root);
            }
            return Err(integration(error.to_string()));
        }
        if had_previous {
            let _ = std::fs::remove_dir_all(previous);
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&staging);
    }
    result
}

fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    std::fs::create_dir_all(to).map_err(|error| integration(error.to_string()))?;
    for entry in std::fs::read_dir(from).map_err(|error| integration(error.to_string()))? {
        let entry = entry.map_err(|error| integration(error.to_string()))?;
        let kind = entry
            .file_type()
            .map_err(|error| integration(error.to_string()))?;
        let name = entry.file_name();
        // Tests and other development files are not part of the runtime.
        if name == "tests" || name == "node_modules" {
            continue;
        }
        if kind.is_dir() {
            copy_tree(&entry.path(), &to.join(&name))?;
        } else if kind.is_file() {
            std::fs::copy(entry.path(), to.join(&name))
                .map_err(|error| integration(error.to_string()))?;
        }
    }
    Ok(())
}

fn runtime_path(root: &Path) -> Result<String> {
    let path = root.join(RUNTIME);
    let path = path
        .to_str()
        .ok_or_else(|| integration("the Patronus data directory is not valid UTF-8"))?;
    // Windows separators become `/`, which Node accepts there too, so the command quotes the same
    // way in bash and PowerShell. A backslash left elsewhere would be an escape inside the quotes.
    #[cfg(windows)]
    let path = path.replace('\\', "/");
    #[cfg(not(windows))]
    let path = path.to_owned();
    // Copilot runs hook commands through bash or PowerShell; refuse paths quoting cannot carry.
    if path.contains(['"', '$', '`', '\\', '\n']) {
        return Err(integration(
            "the Patronus data directory contains characters Copilot hooks cannot quote",
        ));
    }
    Ok(path)
}

fn hook_command(runtime: &str, event: &str) -> String {
    format!("node \"{runtime}\" hook copilot {event}")
}

/// The whole Patronus hook file: Patronus owns it, so it is written in full.
fn hook_file(runtime: &str, enabled: bool) -> Value {
    let hooks: Map<String, Value> = EVENTS
        .iter()
        .map(|(event, timeout)| {
            (
                (*event).to_owned(),
                json!([{ "type": "command", "command": hook_command(runtime, event), "timeoutSec": timeout }]),
            )
        })
        .collect();
    json!({ "version": 1, "disableAllHooks": !enabled, "hooks": hooks })
}

/// A file at Patronus' path that it did not write is never overwritten or removed.
fn is_patronus_file(value: &Value) -> bool {
    let Some(hooks) = value.get("hooks").and_then(Value::as_object) else {
        return value.as_object().is_some_and(Map::is_empty);
    };
    hooks
        .values()
        .filter_map(Value::as_array)
        .flatten()
        .all(|entry| {
            entry
                .get("command")
                .and_then(Value::as_str)
                .is_some_and(|command| command.contains(MARKER))
        })
}

fn read_json(path: &Path) -> Result<(Vec<u8>, Value)> {
    match std::fs::read(path) {
        Ok(bytes) if bytes.iter().all(u8::is_ascii_whitespace) => Ok((bytes, json!({}))),
        Ok(bytes) => {
            let value = serde_json::from_slice::<Value>(&bytes).map_err(|error| {
                integration(format!("{} is not valid JSON: {error}", path.display()))
            })?;
            if !value.is_object() {
                return Err(integration(format!(
                    "{} must contain a JSON object",
                    path.display()
                )));
            }
            Ok((bytes, value))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok((Vec::new(), json!({}))),
        Err(error) => Err(integration(format!(
            "could not read {}: {error}",
            path.display()
        ))),
    }
}

fn write_json(path: &Path, original: &[u8], value: &Value) -> Result<()> {
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|error| integration(error.to_string()))?;
    bytes.push(b'\n');
    if bytes == original {
        return Ok(());
    }
    atomic_write(path, original, &bytes)
}

/// Writes the hook file for `(root, enabled)`, or removes it for `None`.
fn set_hooks(config: &Path, target: Option<(&Path, bool)>) -> Result<()> {
    let path = config.join("hooks").join(HOOK_FILE);
    let (original, existing) = read_json(&path)?;
    if !original.is_empty() && !is_patronus_file(&existing) {
        return Err(integration(format!(
            "{} was not written by Patronus; rename or remove it first",
            path.display()
        )));
    }
    match target {
        Some((root, enabled)) => {
            write_json(&path, &original, &hook_file(&runtime_path(root)?, enabled))
        }
        None => match std::fs::remove_file(&path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(integration(
                format!("could not remove {}: {error}", path.display()),
            )),
            _ => Ok(()),
        },
    }
}

fn patch_mcp(config: &mut Value, runtime: Option<&str>) -> Result<()> {
    let object = config
        .as_object_mut()
        .ok_or_else(|| integration("mcp-config.json must be an object"))?;
    let servers = object.entry("mcpServers").or_insert_with(|| json!({}));
    let servers = servers
        .as_object_mut()
        .ok_or_else(|| integration("mcp-config.json field mcpServers must be an object"))?;
    if let Some(existing) = servers.get(MCP_SERVER) {
        if !is_patronus_server(existing) {
            return Err(integration(
                "mcp-config.json already defines a different server named patronus; rename or remove it first",
            ));
        }
    }
    match runtime {
        Some(runtime) => {
            servers.insert(
                MCP_SERVER.into(),
                json!({ "type": "stdio", "command": "node", "args": [runtime, "mcp"], "tools": ["*"] }),
            );
        }
        None => {
            servers.remove(MCP_SERVER);
        }
    }
    Ok(())
}

fn is_patronus_server(server: &Value) -> bool {
    server
        .get("args")
        .and_then(Value::as_array)
        .and_then(|args| args.first())
        .and_then(Value::as_str)
        .is_some_and(|path| path.ends_with(RUNTIME))
}

fn set_mcp(config: &Path, root: Option<&Path>) -> Result<()> {
    let runtime = root.map(runtime_path).transpose()?;
    let path = config.join("mcp-config.json");
    let (original, mut value) = read_json(&path)?;
    patch_mcp(&mut value, runtime.as_deref())?;
    write_json(&path, &original, &value)
}

struct State {
    reachable: bool,
    installed: Option<bool>,
    enabled: Option<bool>,
}

fn read_state(config: &Path, root: &Path) -> State {
    let hooks = read_json(&config.join("hooks").join(HOOK_FILE))
        .ok()
        .map(|(_, value)| value);
    let mcp = read_json(&config.join("mcp-config.json"))
        .ok()
        .map(|(_, value)| value);
    let (Some(hooks), Some(mcp)) = (hooks, mcp) else {
        return State {
            reachable: false,
            installed: None,
            enabled: None,
        };
    };
    let installed = root.join(RUNTIME).is_file()
        && mcp
            .get("mcpServers")
            .and_then(|servers| servers.get(MCP_SERVER))
            .is_some_and(is_patronus_server);
    let enabled = runtime_path(root)
        .ok()
        .is_some_and(|runtime| hooks == hook_file(&runtime, true));
    State {
        reachable: true,
        installed: Some(installed),
        enabled: Some(installed && enabled),
    }
}

fn status(config: &Path, root: &Path) -> IntegrationStatus {
    let state = read_state(config, root);
    let ready = state.reachable && state.enabled == Some(true);
    let (state_name, message) = if ready {
        ("active", "The Patronus Copilot hooks and MCP server are configured. Start a new copilot session to load them.")
    } else if !state.reachable {
        ("unreachable", "Copilot's hooks/patronus-security.json or mcp-config.json cannot be read. Fix the reported file, then enable Patronus or uninstall it explicitly.")
    } else if state.installed != Some(true) {
        ("not_installed", "The Patronus Copilot plugin is not installed for this user. Install it before enabling it.")
    } else {
        (
            "disabled",
            "The Patronus Copilot plugin is installed but its hooks are disabled.",
        )
    };
    IntegrationStatus::new(
        IntegrationHost::Copilot,
        IntegrationScope::User,
        None,
        StatusObservation {
            installed: state.installed,
            enabled: state.enabled,
            reachable: state.reachable,
            ready,
            state: state_name,
            message,
        },
    )
}

fn integration(message: impl Into<String>) -> ScannerError {
    ScannerError::Integration(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUNTIME_PATH: &str =
        "/home/user/.patronus-security-scanner/integrations/copilot/scripts/patronus.mjs";

    #[test]
    fn the_hook_file_registers_every_event_and_switches_with_disable_all_hooks() {
        let on = hook_file(RUNTIME_PATH, true);
        assert_eq!(on["version"], 1);
        assert_eq!(on["disableAllHooks"], false);
        for (event, timeout) in EVENTS {
            assert_eq!(
                on["hooks"][event],
                json!([{ "type": "command", "command": format!("node \"{RUNTIME_PATH}\" hook copilot {event}"), "timeoutSec": timeout }])
            );
        }
        assert_eq!(hook_file(RUNTIME_PATH, false)["disableAllHooks"], true);
        assert!(is_patronus_file(&on));
        assert!(is_patronus_file(&json!({})));
        assert!(!is_patronus_file(
            &json!({"version": 1, "hooks": {"preToolUse": [{"command": "./audit.sh"}]}})
        ));
    }

    #[test]
    fn mcp_server_is_added_and_removed_without_touching_others() {
        let mut config = json!({"mcpServers": {"github": {"type": "http", "url": "https://example.test/mcp", "tools": ["*"]}}});
        patch_mcp(&mut config, Some(RUNTIME_PATH)).unwrap();
        assert_eq!(
            config["mcpServers"]["patronus"],
            json!({"type": "stdio", "command": "node", "args": [RUNTIME_PATH, "mcp"], "tools": ["*"]})
        );
        patch_mcp(&mut config, None).unwrap();
        assert_eq!(
            config,
            json!({"mcpServers": {"github": {"type": "http", "url": "https://example.test/mcp", "tools": ["*"]}}})
        );
    }

    #[test]
    fn a_foreign_server_named_patronus_is_not_overwritten() {
        let mut config = json!({"mcpServers": {"patronus": {"command": "other-tool"}}});
        assert!(patch_mcp(&mut config, Some(RUNTIME_PATH)).is_err());
        assert!(patch_mcp(&mut config, None).is_err());
        assert!(patch_mcp(&mut json!({"mcpServers": []}), Some(RUNTIME_PATH)).is_err());
    }

    #[test]
    fn unsafe_runtime_paths_are_refused() {
        assert!(runtime_path(Path::new("/tmp/a\"b")).is_err());
        assert!(runtime_path(Path::new("/tmp/$HOME")).is_err());
        assert!(runtime_path(Path::new("/tmp/ok")).is_ok());
    }

    #[test]
    fn lifecycle_round_trip_in_isolated_directories() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        for dir in ["hooks", "scripts", "tests"] {
            std::fs::create_dir_all(source.join(dir)).unwrap();
        }
        std::fs::write(source.join(MANIFEST), "{\"name\":\"patronus-security\"}").unwrap();
        std::fs::write(source.join(HOOKS), "{\"version\":1,\"hooks\":{}}").unwrap();
        std::fs::write(source.join(RUNTIME), "// runtime").unwrap();
        std::fs::write(source.join("tests/fixture.mjs"), "").unwrap();
        let config = temp.path().join("copilot-home");
        std::fs::create_dir_all(config.join("hooks")).unwrap();
        let foreign = "{\"version\":1,\"hooks\":{\"sessionEnd\":[{\"command\":\"./mine.sh\"}]}}";
        std::fs::write(config.join("hooks/mine.json"), foreign).unwrap();
        let root = temp.path().join("data/integrations/copilot");

        let state = read_state(&config, &root);
        assert_eq!(
            (state.reachable, state.installed, state.enabled),
            (true, Some(false), Some(false))
        );

        // A repository checkout resolves to plugins/copilot.
        std::fs::create_dir_all(temp.path().join("checkout/plugins")).unwrap();
        std::fs::rename(&source, temp.path().join("checkout/plugins/copilot")).unwrap();
        let source = plugin_source(Some(&temp.path().join("checkout"))).unwrap();
        copy_plugin(&source, &root).unwrap();
        assert!(!root.join("tests").exists());
        set_mcp(&config, Some(&root)).unwrap();
        set_hooks(&config, Some((&root, true))).unwrap();
        let state = read_state(&config, &root);
        assert_eq!((state.installed, state.enabled), (Some(true), Some(true)));

        set_hooks(&config, Some((&root, false))).unwrap();
        let state = read_state(&config, &root);
        assert_eq!((state.installed, state.enabled), (Some(true), Some(false)));

        set_hooks(&config, None).unwrap();
        set_mcp(&config, None).unwrap();
        assert!(!config.join("hooks").join(HOOK_FILE).exists());
        assert_eq!(
            std::fs::read_to_string(config.join("hooks/mine.json")).unwrap(),
            foreign
        );

        // A foreign file at Patronus' path is left alone.
        std::fs::write(config.join("hooks").join(HOOK_FILE), foreign).unwrap();
        assert!(set_hooks(&config, Some((&root, true))).is_err());
        assert!(set_hooks(&config, None).is_err());

        std::fs::write(config.join("mcp-config.json"), "not json").unwrap();
        assert!(!read_state(&config, &root).reachable);
    }
}
