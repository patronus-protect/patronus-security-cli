use std::path::{Path, PathBuf};

use crate::cli::{IntegrationAction, IntegrationArgs};
use crate::error::{Result, ScannerError};

use super::{discover_root, executable, run, IntegrationStatus, StatusObservation};

const MARKETPLACE: &str = "patronus-local";
const SELECTOR: &str = "patronus-security@patronus-local";
const MARKETPLACE_MARKER: &str = ".claude-plugin/marketplace.json";

pub(super) fn execute(args: IntegrationArgs) -> Result<()> {
    let claude = executable("PATRONUS_CLAUDE_BIN", "claude");
    let scope = args.scope.as_str();

    match args.action {
        IntegrationAction::Update => {
            super::require_success(&claude, &["plugin", "update", "--scope", scope, SELECTOR])
        }
        IntegrationAction::Install => {
            let source = marketplace_source(args.source.as_deref())?;
            let source = source.to_str().ok_or_else(|| {
                ScannerError::Integration(format!(
                    "Claude marketplace path is not valid UTF-8: {}",
                    source.display()
                ))
            })?;
            invoke(
                &claude,
                &["plugin", "marketplace", "add", "--scope", scope, source],
                Already::MarketplacePresent,
            )?;
            invoke(
                &claude,
                &["plugin", "install", "--scope", scope, SELECTOR],
                Already::PluginInstalled,
            )?;
            invoke(
                &claude,
                &["plugin", "enable", "--scope", scope, SELECTOR],
                Already::PluginEnabled,
            )
        }
        IntegrationAction::Enable => invoke(
            &claude,
            &["plugin", "enable", "--scope", scope, SELECTOR],
            Already::PluginEnabled,
        ),
        IntegrationAction::Disable => invoke(
            &claude,
            &["plugin", "disable", "--scope", scope, SELECTOR],
            Already::PluginDisabled,
        ),
        IntegrationAction::Uninstall => {
            let mut uninstall = vec!["plugin", "uninstall", "--scope", scope, "-y"];
            if args.keep_data {
                uninstall.push("--keep-data");
            }
            uninstall.push(SELECTOR);
            invoke(&claude, &uninstall, Already::PluginAbsent)
        }
        IntegrationAction::Status { format } => status(&claude, args.scope).print(format),
    }
}

pub(super) fn dashboard_status() -> Result<IntegrationStatus> {
    let binary = executable("PATRONUS_CLAUDE_BIN", "claude");
    Ok(status(&binary, crate::cli::IntegrationScope::User))
}

fn status(claude: &Path, scope: crate::cli::IntegrationScope) -> IntegrationStatus {
    let listed = run(claude, &["plugin", "list", "--json"])
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| parse_status(&output.stdout, scope.as_str()));
    let reachable = listed.is_some();
    let (installed, enabled) = listed.unwrap_or((None, None));
    let ready = reachable && installed == Some(true) && enabled == Some(true);
    let (state, message) = if ready {
        ("active", "The Claude plugin is installed and enabled.")
    } else if !reachable {
        ("unreachable", "Claude is unavailable or its plugin state cannot be read. Restore the Claude CLI, then enable Patronus or disable/uninstall it explicitly.")
    } else if installed != Some(true) {
        ("not_installed", "The Patronus Claude plugin is not installed in this scope. Install it before enabling it.")
    } else {
        (
            "disabled",
            "The Patronus Claude plugin is installed but disabled.",
        )
    };
    IntegrationStatus::new(
        crate::cli::IntegrationHost::Claude,
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

fn parse_status(stdout: &[u8], scope: &str) -> Option<(Option<bool>, Option<bool>)> {
    let plugins = serde_json::from_slice::<serde_json::Value>(stdout).ok()?;
    let plugin = plugins.as_array()?.iter().find(|plugin| {
        plugin.get("id").and_then(serde_json::Value::as_str) == Some(SELECTOR)
            && plugin.get("scope").and_then(serde_json::Value::as_str) == Some(scope)
    });
    Some(match plugin {
        Some(plugin) => (
            Some(true),
            plugin.get("enabled").and_then(serde_json::Value::as_bool),
        ),
        None => (Some(false), Some(false)),
    })
}

fn marketplace_source(explicit: Option<&Path>) -> Result<PathBuf> {
    let source = match explicit {
        Some(path) => path.to_path_buf(),
        None => {
            let cwd = std::env::current_dir().map_err(|error| {
                ScannerError::Integration(format!("could not determine current directory: {error}"))
            })?;
            discover_root(&cwd, Path::new(MARKETPLACE_MARKER)).ok_or_else(|| {
                ScannerError::Integration(format!(
                    "could not find {MARKETPLACE_MARKER}; pass --source <marketplace-root>"
                ))
            })?
        }
    };
    if !source.join(MARKETPLACE_MARKER).is_file() {
        return Err(ScannerError::Integration(format!(
            "Claude marketplace root {} does not contain {MARKETPLACE_MARKER}",
            source.display()
        )));
    }
    Ok(source)
}

#[derive(Clone, Copy)]
enum Already {
    MarketplacePresent,
    PluginInstalled,
    PluginEnabled,
    PluginDisabled,
    PluginAbsent,
}

fn invoke(program: &Path, args: &[&str], already: Already) -> Result<()> {
    let output = run(program, args)?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if already.accepts(&stderr) {
        return Ok(());
    }
    let detail = stderr.trim();
    Err(ScannerError::Integration(format!(
        "{} {} failed{}",
        program.display(),
        args.join(" "),
        if detail.is_empty() {
            String::new()
        } else {
            format!(": {detail}")
        }
    )))
}

impl Already {
    fn accepts(self, stderr: &str) -> bool {
        let message = stderr.to_ascii_lowercase();
        match self {
            Self::MarketplacePresent => {
                message.contains(MARKETPLACE) && message.contains("already exists")
            }
            Self::PluginInstalled => {
                message.contains(SELECTOR) && message.contains("already installed")
            }
            Self::PluginEnabled => {
                message.contains(SELECTOR) && message.contains("already enabled")
            }
            Self::PluginDisabled => {
                message.contains(SELECTOR) && message.contains("already disabled")
            }
            Self::PluginAbsent => {
                message.contains(SELECTOR)
                    && (message.contains("not installed") || message.contains("not found"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::sync::Mutex;

    #[cfg(unix)]
    use crate::cli::{IntegrationHost, IntegrationScope};

    use super::*;

    #[cfg(unix)]
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[cfg(unix)]
    fn args(
        action: IntegrationAction,
        source: Option<PathBuf>,
        keep_data: bool,
    ) -> IntegrationArgs {
        IntegrationArgs {
            host: IntegrationHost::Claude,
            action,
            source,
            scope: IntegrationScope::Project,
            profile: None,
            keep_data,
        }
    }

    #[test]
    fn only_accepts_errors_for_the_exact_patronus_target_and_state() {
        assert!(Already::PluginEnabled.accepts(&format!("{SELECTOR} is already enabled")));
        assert!(!Already::PluginEnabled.accepts("another-plugin is already enabled"));
        assert!(!Already::PluginEnabled.accepts(&format!("{SELECTOR} failed to enable")));
    }

    #[test]
    fn status_uses_the_exact_plugin_and_scope() {
        let json = format!(
            r#"[{{"id":"{SELECTOR}","scope":"user","enabled":true}},{{"id":"other","scope":"project","enabled":true}}]"#
        );
        assert_eq!(
            parse_status(json.as_bytes(), "user"),
            Some((Some(true), Some(true)))
        );
        assert_eq!(
            parse_status(json.as_bytes(), "project"),
            Some((Some(false), Some(false)))
        );
    }

    #[cfg(unix)]
    #[test]
    fn install_and_uninstall_use_native_claude_commands_in_order() {
        use std::os::unix::fs::PermissionsExt;

        let _guard = ENV_LOCK.lock().unwrap();
        let root = std::env::temp_dir().join(format!(
            "patronus-claude-lifecycle-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let marketplace = root.join("marketplace");
        fs::create_dir_all(marketplace.join(".claude-plugin")).unwrap();
        fs::write(marketplace.join(MARKETPLACE_MARKER), "{}").unwrap();
        let log = root.join("calls.log");
        let fake = root.join("claude");
        fs::write(
            &fake,
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$PATRONUS_CLAUDE_TEST_LOG\"\n",
        )
        .unwrap();
        let mut permissions = fs::metadata(&fake).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&fake, permissions).unwrap();

        unsafe {
            std::env::set_var("PATRONUS_CLAUDE_BIN", &fake);
            std::env::set_var("PATRONUS_CLAUDE_TEST_LOG", &log);
        }
        execute(args(
            IntegrationAction::Install,
            Some(marketplace.clone()),
            false,
        ))
        .unwrap();
        execute(args(IntegrationAction::Disable, None, false)).unwrap();
        execute(args(IntegrationAction::Enable, None, false)).unwrap();
        execute(args(IntegrationAction::Uninstall, None, true)).unwrap();
        unsafe {
            std::env::remove_var("PATRONUS_CLAUDE_BIN");
            std::env::remove_var("PATRONUS_CLAUDE_TEST_LOG");
        }

        let calls = fs::read_to_string(log).unwrap();
        let expected = format!(
            "plugin marketplace add --scope project {}\n\
             plugin install --scope project {SELECTOR}\n\
             plugin enable --scope project {SELECTOR}\n\
             plugin disable --scope project {SELECTOR}\n\
             plugin enable --scope project {SELECTOR}\n\
             plugin uninstall --scope project -y --keep-data {SELECTOR}\n",
            marketplace.display()
        );
        assert_eq!(calls, expected);
        fs::remove_dir_all(root).unwrap();
    }
}
