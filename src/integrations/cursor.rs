//! Cursor lifecycle. Cursor's `agent plugin` commands require a Cursor login, so Patronus
//! manages its own entries in the user-level `hooks.json` and `mcp.json` directly and keeps
//! every other entry in those files unchanged. The hook runtime is a verified copy of the
//! released Cursor plugin under the Patronus data directory.
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::{atomic_write, discover_root, IntegrationStatus, StatusObservation};
use crate::cli::{IntegrationAction, IntegrationArgs, IntegrationHost, IntegrationScope};
use crate::error::{Result, ScannerError};

/// Cursor events Patronus registers, with their hook timeouts in seconds.
const EVENTS: [(&str, u64); 5] = [
    ("beforeSubmitPrompt", 90),
    ("beforeReadFile", 90),
    ("postToolUse", 90),
    ("stop", 30),
    ("sessionEnd", 30),
];
const MANIFEST: &str = ".cursor-plugin/plugin.json";
const RUNTIME: &str = "scripts/patronus.mjs";
const MCP_SERVER: &str = "patronus";
/// Every Patronus hook command contains this marker; nothing else is touched.
const MARKER: &str = "/scripts/patronus.mjs\" hook cursor ";

pub(super) fn execute(args: IntegrationArgs) -> Result<()> {
    if args.scope != IntegrationScope::User {
        return Err(integration("Cursor lifecycle supports only --scope user"));
    }
    let config = config_dir()?;
    let root = install_root()?;
    match args.action {
        IntegrationAction::Install => {
            let source = plugin_source(args.source.as_deref())?;
            copy_plugin(&source, &root)?;
            set_mcp(&config, Some(&root))?;
            set_hooks(&config, Some(&root))
        }
        IntegrationAction::Update => {
            let enabled = read_state(&config, &root).enabled == Some(true);
            let source = plugin_source(args.source.as_deref())?;
            copy_plugin(&source, &root)?;
            set_mcp(&config, Some(&root))?;
            set_hooks(&config, enabled.then_some(root.as_path()))
        }
        IntegrationAction::Enable => {
            if !root.join(RUNTIME).is_file() {
                return Err(integration(
                    "the Patronus Cursor plugin is not installed; run integration cursor install",
                ));
            }
            set_mcp(&config, Some(&root))?;
            set_hooks(&config, Some(&root))
        }
        IntegrationAction::Disable => set_hooks(&config, None),
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

/// Mirrors Cursor's own lookup: `CURSOR_CONFIG_DIR`, then `$XDG_CONFIG_HOME/cursor`, then `~/.cursor`.
fn config_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("CURSOR_CONFIG_DIR").filter(|dir| !dir.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME").filter(|dir| !dir.is_empty()) {
        return Ok(PathBuf::from(dir).join("cursor"));
    }
    directories::BaseDirs::new()
        .map(|dirs| dirs.home_dir().join(".cursor"))
        .ok_or_else(|| integration("cannot resolve the user home directory"))
}

fn install_root() -> Result<PathBuf> {
    Ok(crate::config::user_root()?
        .join("integrations")
        .join("cursor"))
}

fn plugin_source(explicit: Option<&Path>) -> Result<PathBuf> {
    let source = match explicit {
        Some(path) => path.to_path_buf(),
        None => {
            let cwd = std::env::current_dir().map_err(|error| integration(error.to_string()))?;
            discover_root(&cwd, Path::new(MANIFEST)).ok_or_else(|| {
                integration(format!(
                    "could not find {MANIFEST}; pass --source <plugin-root>"
                ))
            })?
        }
    };
    // A release archive or marketplace checkout may hold the plugin under plugins/cursor.
    let source = if source.join(MANIFEST).is_file() {
        source
    } else {
        source.join("plugins").join("cursor")
    };
    if !source.join(MANIFEST).is_file() || !source.join(RUNTIME).is_file() {
        return Err(integration(format!(
            "{} does not contain the Cursor plugin ({MANIFEST} and {RUNTIME})",
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
    let staging = parent.join(format!(".cursor-{:016x}", rand::random::<u64>()));
    let result = (|| {
        copy_tree(source, &staging)?;
        let previous = parent.join(format!(".cursor-old-{:016x}", rand::random::<u64>()));
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
    // Cursor runs hook commands through a shell; refuse paths that quoting cannot carry safely.
    if path.contains(['"', '$', '`', '\\', '\n']) {
        return Err(integration(
            "the Patronus data directory contains characters Cursor hooks cannot quote",
        ));
    }
    Ok(path.to_owned())
}

fn hook_command(runtime: &str, event: &str) -> String {
    format!("node \"{runtime}\" hook cursor {event}")
}

fn is_patronus_hook(entry: &Value) -> bool {
    entry
        .get("command")
        .and_then(Value::as_str)
        .is_some_and(|command| command.contains(MARKER))
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

/// Removes every Patronus hook, then adds the current ones when `root` is given.
fn patch_hooks(config: &mut Value, runtime: Option<&str>) -> Result<()> {
    let object = config
        .as_object_mut()
        .ok_or_else(|| integration("hooks.json must be an object"))?;
    object.entry("version").or_insert(json!(1));
    let hooks = object.entry("hooks").or_insert_with(|| json!({}));
    let hooks = hooks
        .as_object_mut()
        .ok_or_else(|| integration("hooks.json field hooks must be an object"))?;
    for entries in hooks.values_mut() {
        if let Some(entries) = entries.as_array_mut() {
            entries.retain(|entry| !is_patronus_hook(entry));
        }
    }
    if let Some(runtime) = runtime {
        for (event, timeout) in EVENTS {
            let entries = hooks.entry(event).or_insert_with(|| json!([]));
            let entries = entries
                .as_array_mut()
                .ok_or_else(|| integration(format!("hooks.json event {event} must be an array")))?;
            entries.push(json!({ "command": hook_command(runtime, event), "timeout": timeout }));
        }
    }
    hooks.retain(|_, entries| entries.as_array().is_none_or(|entries| !entries.is_empty()));
    Ok(())
}

fn patch_mcp(config: &mut Value, runtime: Option<&str>) -> Result<()> {
    let object = config
        .as_object_mut()
        .ok_or_else(|| integration("mcp.json must be an object"))?;
    let servers = object.entry("mcpServers").or_insert_with(|| json!({}));
    let servers = servers
        .as_object_mut()
        .ok_or_else(|| integration("mcp.json field mcpServers must be an object"))?;
    if let Some(existing) = servers.get(MCP_SERVER) {
        if !is_patronus_server(existing) {
            return Err(integration(
                "mcp.json already defines a different server named patronus; rename or remove it first",
            ));
        }
    }
    match runtime {
        Some(runtime) => {
            servers.insert(
                MCP_SERVER.into(),
                json!({ "type": "stdio", "command": "node", "args": [runtime, "mcp"] }),
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

fn set_hooks(config: &Path, root: Option<&Path>) -> Result<()> {
    let runtime = root.map(runtime_path).transpose()?;
    let path = config.join("hooks.json");
    let (original, mut value) = read_json(&path)?;
    patch_hooks(&mut value, runtime.as_deref())?;
    write_json(&path, &original, &value)
}

fn set_mcp(config: &Path, root: Option<&Path>) -> Result<()> {
    let runtime = root.map(runtime_path).transpose()?;
    let path = config.join("mcp.json");
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
    let hooks = read_json(&config.join("hooks.json"))
        .ok()
        .map(|(_, value)| value);
    let mcp = read_json(&config.join("mcp.json"))
        .ok()
        .map(|(_, value)| value);
    let (Some(hooks), Some(mcp)) = (hooks, mcp) else {
        return State {
            reachable: false,
            installed: None,
            enabled: None,
        };
    };
    let runtime = runtime_path(root).ok();
    let installed = root.join(RUNTIME).is_file()
        && mcp
            .get("mcpServers")
            .and_then(|servers| servers.get(MCP_SERVER))
            .is_some_and(is_patronus_server);
    let enabled = runtime.is_some_and(|runtime| hooks_enabled(&hooks, &runtime));
    State {
        reachable: true,
        installed: Some(installed),
        enabled: Some(installed && enabled),
    }
}

fn hooks_enabled(hooks: &Value, runtime: &str) -> bool {
    EVENTS.iter().all(|(event, _)| {
        let command = hook_command(runtime, event);
        hooks
            .get("hooks")
            .and_then(|hooks| hooks.get(*event))
            .and_then(Value::as_array)
            .is_some_and(|entries| {
                entries.iter().any(|entry| {
                    entry.get("command").and_then(Value::as_str) == Some(command.as_str())
                })
            })
    })
}

fn status(config: &Path, root: &Path) -> IntegrationStatus {
    let state = read_state(config, root);
    let ready = state.reachable && state.enabled == Some(true);
    let (state_name, message) = if ready {
        ("active", "The Patronus Cursor hooks and MCP server are configured. Restart Cursor or start a new cursor-agent session to load them.")
    } else if !state.reachable {
        ("unreachable", "Cursor's hooks.json or mcp.json cannot be read. Fix the reported file, then enable Patronus or uninstall it explicitly.")
    } else if state.installed != Some(true) {
        ("not_installed", "The Patronus Cursor plugin is not installed for this user. Install it before enabling it.")
    } else {
        (
            "disabled",
            "The Patronus Cursor plugin is installed but its hooks are disabled.",
        )
    };
    IntegrationStatus::new(
        IntegrationHost::Cursor,
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
        "/home/user/.patronus-security-scanner/integrations/cursor/scripts/patronus.mjs";

    #[test]
    fn enabling_keeps_foreign_hooks_and_is_idempotent() {
        let mut config = json!({"version": 1, "hooks": {"postToolUse": [{"command": "./audit.sh"}], "afterFileEdit": [{"command": "./format.sh"}]}});
        patch_hooks(&mut config, Some(RUNTIME_PATH)).unwrap();
        let once = config.clone();
        patch_hooks(&mut config, Some(RUNTIME_PATH)).unwrap();
        assert_eq!(config, once);
        assert!(hooks_enabled(&config, RUNTIME_PATH));
        let post = config["hooks"]["postToolUse"].as_array().unwrap();
        assert_eq!(post.len(), 2);
        assert_eq!(post[0]["command"], "./audit.sh");
        assert_eq!(
            post[1]["command"],
            format!("node \"{RUNTIME_PATH}\" hook cursor postToolUse")
        );
        assert_eq!(
            config["hooks"]["afterFileEdit"][0]["command"],
            "./format.sh"
        );
    }

    #[test]
    fn disabling_removes_only_patronus_hooks() {
        let mut config = json!({"hooks": {"stop": [{"command": "./notify.sh"}]}});
        patch_hooks(&mut config, Some(RUNTIME_PATH)).unwrap();
        patch_hooks(&mut config, None).unwrap();
        assert_eq!(
            config,
            json!({"version": 1, "hooks": {"stop": [{"command": "./notify.sh"}]}})
        );
        assert!(!hooks_enabled(&config, RUNTIME_PATH));
    }

    #[test]
    fn a_moved_runtime_replaces_stale_patronus_hooks() {
        let mut config = json!({});
        patch_hooks(&mut config, Some("/old/scripts/patronus.mjs")).unwrap();
        patch_hooks(&mut config, Some(RUNTIME_PATH)).unwrap();
        for (event, _) in EVENTS {
            assert_eq!(config["hooks"][event].as_array().unwrap().len(), 1);
        }
        assert!(hooks_enabled(&config, RUNTIME_PATH));
    }

    #[test]
    fn mcp_server_is_added_and_removed_without_touching_others() {
        let mut config = json!({"mcpServers": {"github": {"url": "https://example.test/mcp"}}});
        patch_mcp(&mut config, Some(RUNTIME_PATH)).unwrap();
        assert_eq!(
            config["mcpServers"]["patronus"]["args"],
            json!([RUNTIME_PATH, "mcp"])
        );
        patch_mcp(&mut config, None).unwrap();
        assert_eq!(
            config,
            json!({"mcpServers": {"github": {"url": "https://example.test/mcp"}}})
        );
    }

    #[test]
    fn a_foreign_server_named_patronus_is_not_overwritten() {
        let mut config = json!({"mcpServers": {"patronus": {"command": "other-tool"}}});
        assert!(patch_mcp(&mut config, Some(RUNTIME_PATH)).is_err());
        assert!(patch_mcp(&mut config, None).is_err());
    }

    #[test]
    fn invalid_shapes_are_rejected_instead_of_rewritten() {
        assert!(patch_hooks(&mut json!({"hooks": []}), Some(RUNTIME_PATH)).is_err());
        assert!(patch_hooks(&mut json!({"hooks": {"stop": {}}}), Some(RUNTIME_PATH)).is_err());
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
        std::fs::create_dir_all(source.join(".cursor-plugin")).unwrap();
        std::fs::create_dir_all(source.join("scripts")).unwrap();
        std::fs::create_dir_all(source.join("tests")).unwrap();
        std::fs::write(source.join(MANIFEST), "{\"name\":\"patronus-security\"}").unwrap();
        std::fs::write(source.join(RUNTIME), "// runtime").unwrap();
        std::fs::write(source.join("tests/fixture.mjs"), "").unwrap();
        let config = temp.path().join("cursor");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(
            config.join("hooks.json"),
            "{\"version\":1,\"hooks\":{\"stop\":[{\"command\":\"./mine.sh\"}]}}",
        )
        .unwrap();
        let root = temp.path().join("data/integrations/cursor");

        let state = read_state(&config, &root);
        assert_eq!(
            (state.reachable, state.installed, state.enabled),
            (true, Some(false), Some(false))
        );

        copy_plugin(&plugin_source(Some(&source)).unwrap(), &root).unwrap();
        assert!(!root.join("tests").exists());
        set_mcp(&config, Some(&root)).unwrap();
        set_hooks(&config, Some(&root)).unwrap();
        let state = read_state(&config, &root);
        assert_eq!((state.installed, state.enabled), (Some(true), Some(true)));

        set_hooks(&config, None).unwrap();
        let state = read_state(&config, &root);
        assert_eq!((state.installed, state.enabled), (Some(true), Some(false)));

        // Reinstalling over an existing copy replaces it.
        copy_plugin(&source, &root).unwrap();
        set_hooks(&config, None).unwrap();
        set_mcp(&config, None).unwrap();
        let hooks: Value =
            serde_json::from_slice(&std::fs::read(config.join("hooks.json")).unwrap()).unwrap();
        assert_eq!(hooks["hooks"], json!({"stop": [{"command": "./mine.sh"}]}));

        std::fs::write(config.join("mcp.json"), "not json").unwrap();
        assert!(!read_state(&config, &root).reachable);
    }
}
