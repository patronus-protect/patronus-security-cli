use std::collections::BTreeMap;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::Value;
use toml_edit::{value, DocumentMut, Item, Table};

use super::{
    atomic_write, discover_root, executable, require_success, run, IntegrationStatus,
    StatusObservation,
};
use crate::cli::{IntegrationAction, IntegrationArgs, IntegrationScope};
use crate::error::{Result, ScannerError};

const SELECTOR: &str = "patronus-security@patronus-local";
const HOOK_PREFIX: &str = "patronus-security@patronus-local:hooks/hooks.json:";
const EVENTS: [&str; 5] = [
    "preToolUse",
    "postToolUse",
    "sessionStart",
    "userPromptSubmit",
    "stop",
];

pub(super) fn execute(args: IntegrationArgs) -> Result<()> {
    if args.scope != IntegrationScope::User {
        return Err(integration("Codex lifecycle supports only --scope user"));
    }
    let binary = executable("PATRONUS_CODEX_BIN", "codex");
    let cwd = std::env::current_dir().map_err(|error| integration(error.to_string()))?;
    match args.action {
        IntegrationAction::Update => {
            let enabled = configured_state().is_some_and(|state| state.1);
            // Local marketplaces already read from their source directory; Codex
            // rejects `marketplace upgrade` for them. Reinstall still refreshes
            // the cached plugin and activation renews changed hook hashes.
            let config = std::fs::read_to_string(config_path()?)
                .map_err(|error| integration(error.to_string()))?;
            let config = config
                .parse::<DocumentMut>()
                .map_err(|error| integration(error.to_string()))?;
            let local = config
                .get("marketplaces")
                .and_then(|item| item.get("patronus-local"))
                .and_then(|item| item.get("source_type"))
                .and_then(Item::as_str)
                == Some("local");
            if !local {
                require_success(
                    &binary,
                    &["plugin", "marketplace", "upgrade", "patronus-local"],
                )?;
            }
            require_success(&binary, &["plugin", "add", SELECTOR])?;
            if enabled {
                activate(&binary, &cwd)
            } else {
                edit_config(|doc| set_enabled(doc, false))
            }
        }
        IntegrationAction::Install => install(&binary, args.source.as_deref(), &cwd),
        IntegrationAction::Enable => activate(&binary, &cwd),
        IntegrationAction::Disable => edit_config(|doc| set_enabled(doc, false)),
        IntegrationAction::Uninstall => uninstall(&binary),
        IntegrationAction::Status { format } => status(&binary, args.scope).print(format),
    }
}

pub(super) fn dashboard_status() -> Result<IntegrationStatus> {
    let binary = executable("PATRONUS_CODEX_BIN", "codex");
    Ok(status(&binary, IntegrationScope::User))
}

fn status(binary: &Path, scope: IntegrationScope) -> IntegrationStatus {
    let configured = configured_state();
    let listed = run(
        binary,
        &["plugin", "list", "--marketplace", "patronus-local"],
    )
    .ok()
    .filter(|output| output.status.success())
    .map(|output| listed_state(&output.stdout));
    let reachable = listed.is_some();
    let installed = listed
        .map(|state| state.0)
        .or_else(|| configured.map(|state| state.0));
    let enabled = listed
        .map(|state| state.1)
        .or_else(|| configured.map(|state| state.1));
    // Stored hashes can outlive a changed hook definition. Ask the host whether
    // the installed definitions are still enabled and trusted before claiming ready.
    let hooks_ready = configured.is_some_and(|state| state.2)
        && std::env::current_dir()
            .ok()
            .is_some_and(|cwd| discover_hooks(binary, &cwd, true).is_ok());
    let ready = reachable && installed == Some(true) && enabled == Some(true) && hooks_ready;
    let (state, message) = if ready {
        (
            "active",
            "The installed plugin and all five hooks are trusted for newly loaded tasks. Already running tasks and their subagents may retain old hook trust; reload the parent task after a repair.",
        )
    } else if !reachable {
        ("unreachable", "Codex is unavailable. Restore the Codex CLI, then enable Patronus or disable/uninstall it explicitly.")
    } else if installed != Some(true) {
        (
            "not_installed",
            "The Patronus Codex plugin is not installed. Install it before enabling it.",
        )
    } else if enabled != Some(true) {
        (
            "disabled",
            "The Patronus Codex plugin is installed but disabled.",
        )
    } else {
        ("incomplete", "The Patronus Codex hooks are not fully trusted. Run enable to repair them, or disable/uninstall the integration.")
    };
    IntegrationStatus::new(
        crate::cli::IntegrationHost::Codex,
        scope,
        None,
        StatusObservation {
            installed,
            enabled,
            reachable,
            ready,
            state,
            message,
        },
    )
}

fn listed_state(stdout: &[u8]) -> (bool, bool) {
    let text = String::from_utf8_lossy(stdout);
    let row = text
        .lines()
        .find(|line| line.trim_start().starts_with(SELECTOR));
    (
        row.is_some(),
        row.is_some_and(|line| line.contains("installed, enabled")),
    )
}

fn configured_state() -> Option<(bool, bool, bool)> {
    let bytes = match std::fs::read(config_path().ok()?) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Some((false, false, false))
        }
        Err(_) => return None,
    };
    let document = std::str::from_utf8(&bytes)
        .ok()?
        .parse::<DocumentMut>()
        .ok()?;
    let plugin = document
        .get("plugins")
        .and_then(Item::as_table)
        .and_then(|plugins| plugins.get(SELECTOR));
    let installed = plugin.is_some();
    let enabled = plugin
        .and_then(Item::as_table)
        .and_then(|table| table.get("enabled"))
        .and_then(Item::as_value)
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let state = document
        .get("hooks")
        .and_then(Item::as_table)
        .and_then(|hooks| hooks.get("state"))
        .and_then(Item::as_table);
    let hooks_ready = state.is_some_and(|state| {
        EVENTS.iter().all(|event| {
            state
                .get(&expected_key(event))
                .and_then(Item::as_table)
                .is_some_and(|hook| {
                    hook.get("enabled")
                        .and_then(Item::as_value)
                        .and_then(|value| value.as_bool())
                        == Some(true)
                        && hook
                            .get("trusted_hash")
                            .and_then(Item::as_value)
                            .and_then(|value| value.as_str())
                            .is_some_and(|hash| !hash.is_empty())
                })
        })
    });
    Some((installed, enabled, hooks_ready))
}

fn install(binary: &Path, source: Option<&Path>, cwd: &Path) -> Result<()> {
    let root = source
        .map(Path::to_path_buf)
        .or_else(|| discover_root(cwd, Path::new(".agents/plugins/marketplace.json")))
        .ok_or_else(|| integration("Codex marketplace root not found; pass --source"))?;
    if !root.join(".agents/plugins/marketplace.json").is_file() {
        return Err(integration(format!(
            "{} is not a Patronus marketplace root",
            root.display()
        )));
    }
    let root = root
        .to_str()
        .ok_or_else(|| integration("Codex marketplace path is not valid UTF-8"))?;
    if replace_stale_marketplace(binary, root)? {
        require_success(binary, &["plugin", "marketplace", "add", root])?;
    }
    require_success(binary, &["plugin", "add", SELECTOR])?;
    if let Err(error) = activate(binary, cwd) {
        return match require_success(binary, &["plugin", "remove", SELECTOR]) {
            Ok(()) => Err(error),
            Err(removal) => Err(integration(format!(
                "{error}; could not remove the incompletely installed Codex plugin: {removal}"
            ))),
        };
    }
    Ok(())
}

fn replace_stale_marketplace(binary: &Path, root: &str) -> Result<bool> {
    let path = config_path()?;
    let config = match std::fs::read_to_string(path) {
        Ok(config) => config,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(error) => return Err(integration(error.to_string())),
    };
    let config = config
        .parse::<DocumentMut>()
        .map_err(|error| integration(error.to_string()))?;
    let Some(existing) = config
        .get("marketplaces")
        .and_then(|item| item.get("patronus-local"))
        .and_then(|item| item.get("source"))
        .and_then(Item::as_str)
    else {
        return Ok(true);
    };
    if Path::new(existing) == Path::new(root) {
        return Ok(false);
    }
    if configured_state().is_some_and(|state| state.0) {
        require_success(binary, &["plugin", "remove", SELECTOR])?;
    }
    require_success(
        binary,
        &["plugin", "marketplace", "remove", "patronus-local"],
    )?;
    Ok(true)
}

fn activate(binary: &Path, cwd: &Path) -> Result<()> {
    activation_transaction(
        |enabled| edit_config(|doc| set_enabled(doc, enabled)),
        || discover_hooks(binary, cwd, false),
        |hooks| edit_config(|doc| trust_hooks(doc, hooks)),
    )
}

fn activation_transaction(
    mut set_enabled_state: impl FnMut(bool) -> Result<()>,
    discover: impl FnOnce() -> Result<BTreeMap<String, String>>,
    persist_trust: impl FnOnce(&BTreeMap<String, String>) -> Result<()>,
) -> Result<()> {
    let result = set_enabled_state(true)
        .and_then(|()| discover())
        .and_then(|hooks| persist_trust(&hooks));
    if let Err(error) = result {
        return match set_enabled_state(false) {
            Ok(()) => Err(error),
            Err(rollback) => Err(integration(format!(
                "{error}; could not leave the Codex plugin disabled: {rollback}"
            ))),
        };
    }
    Ok(())
}

fn uninstall(binary: &Path) -> Result<()> {
    require_success(binary, &["plugin", "remove", SELECTOR])?;
    edit_config(|document| {
        remove_plugin_state(document);
        Ok(())
    })
}

fn discover_hooks(
    binary: &Path,
    cwd: &Path,
    require_trusted: bool,
) -> Result<BTreeMap<String, String>> {
    let mut child = Command::new(binary)
        .arg("app-server")
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            integration(format!(
                "could not run {} app-server: {error}",
                binary.display()
            ))
        })?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| integration("Codex app-server stdin unavailable"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| integration("Codex app-server stdout unavailable"))?;
    // Drain diagnostics concurrently: a full stderr pipe can block hooks/list.
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| integration("Codex stderr unavailable"))?;
    let diagnostics = std::thread::spawn(move || {
        let mut stderr = std::io::BufReader::new(stderr);
        let mut bytes = Vec::new();
        let _ = stderr.by_ref().take(65536).read_to_end(&mut bytes);
        let _ = std::io::copy(&mut stderr, &mut std::io::sink());
        String::from_utf8_lossy(&bytes).into_owned()
    });
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout)
            .lines()
            .map_while(std::result::Result::ok)
        {
            let response_id = serde_json::from_str::<Value>(&line)
                .ok()
                .and_then(|message| message.get("id").and_then(Value::as_u64));
            if matches!(response_id, Some(1 | 2)) {
                let _ = sender.send(line.into_bytes());
                if response_id == Some(2) {
                    break;
                }
            }
        }
    });
    let response = (|| -> Result<Vec<u8>> {
        writeln!(stdin, "{}", serde_json::json!({
            "id": 1, "method": "initialize",
            "params": {"clientInfo": {"name": "patronus-security-scanner", "version": env!("CARGO_PKG_VERSION")}, "capabilities": {"experimentalApi": true}}
        })).map_err(|error| integration(format!("could not initialize Codex: {error}")))?;
        let initialized = receiver
            .recv_timeout(Duration::from_secs(20))
            .map_err(|_| integration("Codex initialization timed out or exited"))?;
        let initialized: Value = serde_json::from_slice(&initialized)
            .map_err(|error| integration(format!("invalid Codex initialization: {error}")))?;
        if let Some(error) = initialized.get("error") {
            return Err(integration(format!("Codex initialization failed: {error}")));
        }
        writeln!(stdin, "{}", serde_json::json!({"method": "initialized"}))
            .and_then(|()| {
                writeln!(
                    stdin,
                    "{}",
                    serde_json::json!({"id": 2, "method": "hooks/list", "params": {"cwds": [cwd]}})
                )
            })
            .map_err(|error| integration(format!("could not query Codex hooks: {error}")))?;
        receiver
            .recv_timeout(Duration::from_secs(20))
            .map_err(|_| integration("Codex hook discovery timed out or exited"))
    })();
    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();
    let stderr = diagnostics.join().unwrap_or_default();
    match response {
        Ok(response) => parse_hooks(&response, require_trusted),
        Err(error) => Err(integration(format!("{error}: {}", stderr.trim()))),
    }
}

fn parse_hooks(stdout: &[u8], require_trusted: bool) -> Result<BTreeMap<String, String>> {
    let response = stdout
        .split(|byte| *byte == b'\n')
        .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
        .find(|message| message.get("id").and_then(Value::as_u64) == Some(2))
        .ok_or_else(|| integration("Codex hooks/list returned no response"))?;
    if let Some(error) = response.get("error") {
        return Err(integration(format!("Codex hooks/list failed: {error}")));
    }
    let entries = response
        .pointer("/result/data")
        .and_then(Value::as_array)
        .ok_or_else(|| integration("Codex hooks/list returned an invalid result"))?;
    let mut hooks = BTreeMap::new();
    let mut events = Vec::new();
    for hook in entries
        .iter()
        .filter_map(|entry| entry.get("hooks").and_then(Value::as_array))
        .flatten()
    {
        let key = hook.get("key").and_then(Value::as_str).unwrap_or_default();
        if !key.starts_with(HOOK_PREFIX) {
            continue;
        }
        let event = hook
            .get("eventName")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let hash = hook
            .get("currentHash")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if require_trusted
            && (hook.get("enabled").and_then(Value::as_bool) != Some(true)
                || hook.get("trustStatus").and_then(Value::as_str) != Some("trusted"))
        {
            return Err(integration(
                "An installed Patronus hook is disabled or not trusted",
            ));
        }
        if !EVENTS.contains(&event)
            || key != expected_key(event)
            || hash.is_empty()
            || events.contains(&event)
            || hooks.insert(key.to_owned(), hash.to_owned()).is_some()
        {
            return Err(integration(
                "Codex returned invalid or duplicate Patronus hook metadata",
            ));
        }
        events.push(event);
    }
    if hooks.len() != EVENTS.len() || !EVENTS.iter().all(|event| events.contains(event)) {
        return Err(integration(
            "Codex did not discover all five Patronus hooks",
        ));
    }
    Ok(hooks)
}

fn expected_key(event: &str) -> String {
    let name = match event {
        "preToolUse" => "pre_tool_use",
        "postToolUse" => "post_tool_use",
        "sessionStart" => "session_start",
        "userPromptSubmit" => "user_prompt_submit",
        "stop" => "stop",
        _ => "",
    };
    format!("{HOOK_PREFIX}{name}:0:0")
}

fn config_path() -> Result<PathBuf> {
    if let Some(home) = std::env::var_os("CODEX_HOME") {
        return Ok(PathBuf::from(home).join("config.toml"));
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".codex/config.toml"))
        .ok_or_else(|| integration("CODEX_HOME and HOME are not set"))
}

fn edit_config(edit: impl FnOnce(&mut DocumentMut) -> Result<()>) -> Result<()> {
    let path = config_path()?;
    let original = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(source) => return Err(ScannerError::Io { path, source }),
    };
    let text = std::str::from_utf8(&original)
        .map_err(|_| integration("Codex config.toml is not UTF-8"))?;
    let mut document = text
        .parse::<DocumentMut>()
        .map_err(|error| integration(format!("invalid Codex config.toml: {error}")))?;
    edit(&mut document)?;
    atomic_write(&path, &original, document.to_string().as_bytes())
}

fn set_enabled(document: &mut DocumentMut, enabled: bool) -> Result<()> {
    let plugins = child_table(document.as_table_mut(), "plugins")?;
    let plugin = child_table(plugins, SELECTOR)?;
    plugin.insert("enabled", value(enabled));
    Ok(())
}

fn trust_hooks(document: &mut DocumentMut, hooks: &BTreeMap<String, String>) -> Result<()> {
    remove_hook_state(document);
    let hooks_state = child_table(child_table(document.as_table_mut(), "hooks")?, "state")?;
    for (key, hash) in hooks {
        let mut table = Table::new();
        table.insert("enabled", value(true));
        table.insert("trusted_hash", value(hash));
        hooks_state.insert(key, Item::Table(table));
    }
    Ok(())
}

fn child_table<'a>(parent: &'a mut Table, key: &str) -> Result<&'a mut Table> {
    if !parent.contains_key(key) {
        parent.insert(key, Item::Table(Table::new()));
    }
    parent
        .get_mut(key)
        .and_then(Item::as_table_mut)
        .ok_or_else(|| integration(format!("Codex config field {key:?} must be a table")))
}

fn remove_plugin_state(document: &mut DocumentMut) {
    if let Some(plugins) = document.get_mut("plugins").and_then(Item::as_table_mut) {
        plugins.remove(SELECTOR);
    }
    if document
        .get("plugins")
        .and_then(Item::as_table)
        .is_some_and(Table::is_empty)
    {
        document.as_table_mut().remove("plugins");
    }
    remove_hook_state(document);
}

fn remove_hook_state(document: &mut DocumentMut) {
    if let Some(state) = document
        .get_mut("hooks")
        .and_then(Item::as_table_mut)
        .and_then(|hooks| hooks.get_mut("state"))
        .and_then(Item::as_table_mut)
    {
        state.retain(|key, _| !key.starts_with(HOOK_PREFIX));
    }
    let empty_state = document
        .get("hooks")
        .and_then(Item::as_table)
        .and_then(|hooks| hooks.get("state"))
        .and_then(Item::as_table)
        .is_some_and(Table::is_empty);
    if empty_state {
        if let Some(hooks) = document.get_mut("hooks").and_then(Item::as_table_mut) {
            hooks.remove("state");
        }
    }
    if document
        .get("hooks")
        .and_then(Item::as_table)
        .is_some_and(Table::is_empty)
    {
        document.as_table_mut().remove("hooks");
    }
}

fn integration(message: impl Into<String>) -> ScannerError {
    ScannerError::Integration(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn hook_discovery_drains_diagnostics_before_waiting_for_response() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let binary = root.path().join("codex");
        let response = String::from_utf8(hook_response(5)).unwrap();
        let script = format!(
            "#!/bin/sh\nread -r init\nprintf '%s\\n' '{{\"id\":1,\"result\":{{}}}}'\nread -r initialized\nread -r request\nprintf '%s' '{}' >&2\nprintf '%s\\n' '{}'\n",
            "diagnostic".repeat(16384), response.lines().nth(1).unwrap()
        );
        std::fs::write(&binary, script).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(discover_hooks(&binary, root.path(), true).unwrap().len(), 5);
    }

    fn hook_response(count: usize) -> Vec<u8> {
        let hooks: Vec<_> = EVENTS
            .iter()
            .take(count)
            .enumerate()
            .map(|(index, event)| {
                serde_json::json!({
                    "key": expected_key(event),
                    "eventName": event,
                    "currentHash": format!("hash-{index}"),
                    "enabled": true,
                    "trustStatus": "trusted"
                })
            })
            .collect();
        format!(
            "{{\"id\":1,\"result\":{{}}}}\n{}\n",
            serde_json::json!({"id": 2, "result": {"data": [{"hooks": hooks}]}})
        )
        .into_bytes()
    }

    #[test]
    fn accepts_exactly_five_current_patronus_hooks() {
        let hooks = parse_hooks(&hook_response(5), false).unwrap();
        assert_eq!(hooks.len(), 5);
        assert!(hooks.values().any(|hash| hash == "hash-0"));
    }

    #[test]
    fn readiness_rejects_modified_disabled_or_missing_host_trust() {
        assert!(parse_hooks(&hook_response(5), true).is_ok());
        for (key, value) in [
            ("trustStatus", serde_json::json!("modified")),
            ("trustStatus", serde_json::Value::Null),
            ("enabled", serde_json::json!(false)),
        ] {
            let data = hook_response(5);
            let line = data.split(|byte| *byte == b'\n').nth(1).unwrap();
            let mut response: Value = serde_json::from_slice(line).unwrap();
            response["result"]["data"][0]["hooks"][0][key] = value;
            let bytes = serde_json::to_vec(&response).unwrap();
            assert!(parse_hooks(&bytes, true).is_err());
            // Explicit activation must still discover the new hashes for repair.
            assert!(parse_hooks(&bytes, false).is_ok());
        }
    }

    #[test]
    fn rejects_incomplete_hook_discovery() {
        assert!(parse_hooks(&hook_response(4), false).is_err());
    }

    #[test]
    fn failed_hook_discovery_rolls_activation_back_to_disabled() {
        let states = std::cell::RefCell::new(Vec::new());
        let error = activation_transaction(
            |enabled| {
                states.borrow_mut().push(enabled);
                Ok(())
            },
            || Err(integration("discovery failed")),
            |_| panic!("trust must not be persisted after failed discovery"),
        )
        .unwrap_err();
        assert_eq!(*states.borrow(), [true, false]);
        assert!(error.to_string().contains("discovery failed"));
    }

    #[test]
    fn refreshes_only_patronus_state_and_preserves_other_config() {
        let mut document = "# keep\n[plugins.other]\nenabled = true\n[hooks.state.other]\nenabled = false\ntrusted_hash = \"other-hash\"\n[hooks.state.\"patronus-security@patronus-local:hooks/hooks.json:old:0:0\"]\nenabled = true\ntrusted_hash = \"old\"\n".parse::<DocumentMut>().unwrap();
        set_enabled(&mut document, true).unwrap();
        trust_hooks(
            &mut document,
            &parse_hooks(&hook_response(5), false).unwrap(),
        )
        .unwrap();
        let rendered = document.to_string();
        assert!(rendered.contains("# keep"));
        assert!(rendered.contains("[plugins.other]"));
        assert!(rendered.contains("[hooks.state.other]"));
        assert!(!rendered.contains("trusted_hash = \"old\""));
        assert_eq!(rendered.matches("trusted_hash = \"hash-").count(), 5);
    }

    #[test]
    fn uninstall_removes_only_patronus_plugin_and_hooks() {
        let mut document = format!("[plugins.\"{SELECTOR}\"]\nenabled = true\n[plugins.other]\nenabled = true\n[hooks.state.\"{HOOK_PREFIX}stop:0:0\"]\nenabled = true\n[hooks.state.other]\nenabled = true\n").parse::<DocumentMut>().unwrap();
        remove_plugin_state(&mut document);
        let rendered = document.to_string();
        assert!(!rendered.contains(SELECTOR));
        assert!(!rendered.contains(HOOK_PREFIX));
        assert!(rendered.contains("[plugins.other]"));
        assert!(rendered.contains("[hooks.state.other]"));
    }

    #[test]
    fn fresh_config_creates_plugin_and_hook_tables_without_panicking() {
        let mut document = DocumentMut::new();
        set_enabled(&mut document, true).unwrap();
        trust_hooks(
            &mut document,
            &parse_hooks(&hook_response(5), false).unwrap(),
        )
        .unwrap();
        let rendered = document.to_string();
        assert!(rendered.contains(&format!("[plugins.\"{SELECTOR}\"]")));
        assert_eq!(rendered.matches("trusted_hash = ").count(), 5);
    }

    #[test]
    fn parses_codex_plugin_list_without_accepting_other_plugins() {
        assert_eq!(
            listed_state(b"patronus-security@patronus-local  installed, enabled  0.1.0\n"),
            (true, true)
        );
        assert_eq!(
            listed_state(b"patronus-security@patronus-local  installed, disabled  0.1.0\n"),
            (true, false)
        );
        assert_eq!(
            listed_state(b"other@market  installed, enabled  1.0.0\n"),
            (false, false)
        );
    }
}
