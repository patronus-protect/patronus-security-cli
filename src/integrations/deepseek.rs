use std::path::{Path, PathBuf};

use crate::cli::{IntegrationAction, IntegrationArgs, IntegrationScope};
use crate::error::{Result, ScannerError};

use super::{atomic_write, executable, require_success, run, IntegrationStatus, StatusObservation};

const PACKAGE: &str = "@patronus/deepseek-security";
const BEGIN: &[u8] = b"# patronus-security-scanner:deepseek begin";
const END: &[u8] = b"# patronus-security-scanner:deepseek end";

pub(super) fn execute(args: IntegrationArgs) -> Result<()> {
    if args.scope != IntegrationScope::User {
        return Err(integration_error("DeepSeek supports only --scope user"));
    }
    let profile = args.profile.as_deref().unwrap_or("headless");
    validate_profile(profile)?;

    let home = dsh_home()?;
    let patch = home.join("profiles").join(profile).join("cordis.patch.yml");
    let dsh = executable("PATRONUS_DSH_BIN", "dsh");

    match args.action {
        IntegrationAction::Update => {
            require_installed(&home, profile)?;
            let source = args.source.as_deref().ok_or_else(|| {
                integration_error("DeepSeek update requires --source <release.tgz>")
            })?;
            let source = install_source(Some(source))?;
            require_success(
                &dsh,
                &[
                    "plugin",
                    "--profile",
                    profile,
                    "add",
                    source
                        .to_str()
                        .ok_or_else(|| integration_error("Invalid release path"))?,
                ],
            )
        }
        IntegrationAction::Install => {
            validate_markers(&read_optional(&patch)?)?;
            let was_installed = package_installed(&home, profile)?;
            let source = install_source(args.source.as_deref())?;
            let source = source
                .to_str()
                .ok_or_else(|| integration_error("DeepSeek package path must be valid UTF-8"))?;
            require_success(&dsh, &["plugin", "--profile", profile, "add", source])?;
            let activation = (|| {
                if !package_installed(&home, profile)? {
                    return Err(integration_error(
                        "DeepSeek did not record the Patronus package in the profile",
                    ));
                }
                let current = read_optional(&patch)?;
                validate_markers(&current)?;
                write_and_verify(&dsh, profile, &patch, &current, true)
            })();
            match activation {
                Ok(()) => Ok(()),
                Err(error) => rollback_new_install(&dsh, profile, was_installed, error),
            }
        }
        IntegrationAction::Enable => {
            require_installed(&home, profile)?;
            let current = read_optional(&patch)?;
            write_and_verify(&dsh, profile, &patch, &current, true)
        }
        IntegrationAction::Disable => {
            require_installed(&home, profile)?;
            let current = read_optional(&patch)?;
            write_and_verify(&dsh, profile, &patch, &current, false)
        }
        IntegrationAction::Uninstall => {
            validate_markers(&read_optional(&patch)?)?;
            if package_installed(&home, profile)? {
                require_success(&dsh, &["plugin", "--profile", profile, "remove", PACKAGE])?;
                if package_installed(&home, profile)? {
                    return Err(integration_error(
                        "DeepSeek still reports Patronus installed after uninstall",
                    ));
                }
            }
            let current = read_optional(&patch)?;
            let updated = remove_block(&current)?;
            if updated != current {
                atomic_write(&patch, &current, &updated)?;
            }
            Ok(())
        }
        IntegrationAction::Status { format } => status(&dsh, &home, profile).print(format),
    }
}

pub(super) fn dashboard_status() -> Result<IntegrationStatus> {
    let home = dsh_home()?;
    let binary = executable("PATRONUS_DSH_BIN", "dsh");
    Ok(status(&binary, &home, "headless"))
}

fn status(dsh: &Path, home: &Path, profile: &str) -> IntegrationStatus {
    let installed = package_installed(home, profile).ok();
    let effective = installed.filter(|installed| *installed).and_then(|_| {
        run(dsh, &["--profile", profile, "--dump-config"])
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| effective_disabled(&output.stdout).ok())
            .map(|disabled| !disabled)
    });
    let reachable = if installed == Some(true) {
        effective.is_some()
    } else {
        run(dsh, &["--version"]).is_ok_and(|output| output.status.success())
    };
    let enabled = match installed {
        Some(false) => Some(false),
        Some(true) => effective,
        None => None,
    };
    let ready = reachable && installed == Some(true) && enabled == Some(true);
    let (state, message) = if ready {
        (
            "active",
            "The DeepSeek plugin is installed and active in the effective profile.",
        )
    } else if !reachable {
        ("unreachable", "DeepSeek Harness is unavailable or the effective profile cannot be read. Restore the Harness, then enable Patronus or disable/uninstall it explicitly.")
    } else if installed == Some(false) {
        ("not_installed", "The Patronus DeepSeek plugin is not installed in this profile. Install it before enabling it.")
    } else if installed.is_none() {
        ("incomplete", "The Patronus DeepSeek profile state cannot be verified. Repair the profile, then enable Patronus or disable/uninstall it explicitly.")
    } else {
        (
            "disabled",
            "The Patronus DeepSeek plugin is installed but disabled in the effective profile.",
        )
    };
    IntegrationStatus::new(
        crate::cli::IntegrationHost::Deepseek,
        IntegrationScope::User,
        Some(profile),
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

fn rollback_new_install(
    dsh: &Path,
    profile: &str,
    was_installed: bool,
    error: ScannerError,
) -> Result<()> {
    if was_installed {
        return Err(error);
    }
    match require_success(dsh, &["plugin", "--profile", profile, "remove", PACKAGE]) {
        Ok(()) => Err(error),
        Err(rollback) => Err(integration_error(format!(
            "{error}; could not remove the incomplete DeepSeek installation: {rollback}"
        ))),
    }
}

fn dsh_home() -> Result<PathBuf> {
    if let Some(value) = std::env::var_os("DSH_HOME") {
        if !value.to_string_lossy().trim().is_empty() {
            let path = PathBuf::from(value);
            if let Ok(remainder) = path.strip_prefix("~") {
                return directories::BaseDirs::new()
                    .map(|dirs| dirs.home_dir().join(remainder))
                    .ok_or_else(|| integration_error("could not expand DSH_HOME"));
            }
            return Ok(path);
        }
    }
    directories::BaseDirs::new()
        .map(|dirs| dirs.home_dir().join(".dsh"))
        .ok_or_else(|| integration_error("could not determine the DeepSeek Harness home"))
}

fn package_installed(home: &Path, profile: &str) -> Result<bool> {
    let path = home.join("profiles").join(profile).join("package.json");
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => return Err(ScannerError::Io { path, source }),
    };
    let manifest: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
        integration_error(format!("invalid DeepSeek profile package.json: {error}"))
    })?;
    let dependency = manifest
        .pointer(&format!(
            "/dependencies/{}",
            PACKAGE.replace('~', "~0").replace('/', "~1")
        ))
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| !value.is_empty());
    let bundle_count = manifest
        .pointer("/dsh/profile/bundles")
        .and_then(serde_json::Value::as_array)
        .map(|bundles| {
            bundles
                .iter()
                .filter(|bundle| bundle.as_str() == Some(PACKAGE))
                .count()
        })
        .unwrap_or_default();
    match (dependency, bundle_count) {
        (false, 0) => Ok(false),
        (true, 1) => Ok(true),
        _ => Err(integration_error(
            "DeepSeek profile has inconsistent Patronus package state",
        )),
    }
}

fn require_installed(home: &Path, profile: &str) -> Result<()> {
    if package_installed(home, profile)? {
        Ok(())
    } else {
        Err(integration_error(
            "DeepSeek Patronus plugin is not installed in this profile",
        ))
    }
}

fn write_and_verify(
    dsh: &Path,
    profile: &str,
    patch: &Path,
    current: &[u8],
    enabled: bool,
) -> Result<()> {
    let updated = set_enabled(current, enabled)?;
    atomic_write(patch, current, &updated)?;
    if let Err(error) = verify_effective_state(dsh, profile, enabled) {
        return match atomic_write(patch, &updated, current) {
            Ok(()) => Err(error),
            Err(rollback) => Err(integration_error(format!(
                "{error}; could not restore the DeepSeek profile patch: {rollback}"
            ))),
        };
    }
    Ok(())
}

fn verify_effective_state(dsh: &Path, profile: &str, enabled: bool) -> Result<()> {
    let output = run(dsh, &["--profile", profile, "--dump-config"])?;
    if !output.status.success() {
        return Err(integration_error(format!(
            "DeepSeek could not load the effective profile: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let effective = effective_disabled(&output.stdout)?;
    if effective != enabled {
        Ok(())
    } else {
        Err(integration_error(
            "DeepSeek effective profile does not match the requested Patronus state",
        ))
    }
}

fn effective_disabled(output: &[u8]) -> Result<bool> {
    let text = std::str::from_utf8(output)
        .map_err(|_| integration_error("DeepSeek dump-config output is not UTF-8"))?;
    let mut matching = Vec::new();
    let mut id = None;
    let mut disabled = None;
    let finish = |id: &mut Option<&str>, disabled: &mut Option<bool>, matching: &mut Vec<bool>| {
        if *id == Some("patronus-security") {
            matching.push(disabled.unwrap_or(false));
        }
        *id = None;
        *disabled = None;
    };
    for line in text.lines() {
        let field = if let Some(field) = line.strip_prefix("- ") {
            finish(&mut id, &mut disabled, &mut matching);
            Some(field)
        } else {
            line.strip_prefix("  ")
                .filter(|field| !field.starts_with(' '))
        };
        let Some((key, value)) = field.and_then(|field| field.split_once(':')) else {
            continue;
        };
        match key {
            "id" => id = Some(value.trim()),
            "disabled" if id == Some("patronus-security") => {
                disabled = match value.trim() {
                    "true" => Some(true),
                    "false" => Some(false),
                    _ => return Err(integration_error("invalid disabled value in dump-config")),
                }
            }
            _ => {}
        }
    }
    finish(&mut id, &mut disabled, &mut matching);
    match matching.as_slice() {
        [disabled] => Ok(*disabled),
        _ => Err(integration_error(
            "DeepSeek dump-config must contain exactly one Patronus row with disabled state",
        )),
    }
}

fn install_source(source: Option<&Path>) -> Result<&Path> {
    let source = source.ok_or_else(|| {
        integration_error("DeepSeek install requires --source pointing to a .tgz package")
    })?;
    if source.extension().and_then(|value| value.to_str()) != Some("tgz") {
        return Err(integration_error(
            "DeepSeek install --source must point to a .tgz package",
        ));
    }
    if !source.is_file() {
        return Err(integration_error(format!(
            "DeepSeek package does not exist: {}",
            source.display()
        )));
    }
    Ok(source)
}

fn validate_profile(profile: &str) -> Result<()> {
    if matches!(profile, "" | "." | ".." | "node_modules")
        || profile.contains('/')
        || profile.contains('\\')
    {
        return Err(integration_error("invalid DeepSeek profile name"));
    }
    Ok(())
}

fn read_optional(path: &Path) -> Result<Vec<u8>> {
    match std::fs::read(path) {
        Ok(contents) => Ok(contents),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(source) => Err(ScannerError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn set_enabled(contents: &[u8], enabled: bool) -> Result<Vec<u8>> {
    let block = managed_block(enabled);
    match marker_range(contents)? {
        Some((start, end)) => {
            let mut updated = Vec::with_capacity(contents.len() - (end - start) + block.len());
            updated.extend_from_slice(&contents[..start]);
            updated.extend_from_slice(&block);
            updated.extend_from_slice(&contents[end..]);
            Ok(updated)
        }
        None => {
            if let Some((start, end)) = empty_sequence_range(contents) {
                let mut updated = Vec::with_capacity(contents.len() + block.len());
                updated.extend_from_slice(&contents[..start]);
                updated.extend_from_slice(&block);
                updated.extend_from_slice(&contents[end..]);
                return Ok(updated);
            }
            let mut updated = contents.to_vec();
            if !updated.is_empty() {
                updated.push(b'\n');
            }
            updated.extend_from_slice(&block);
            Ok(updated)
        }
    }
}

fn remove_block(contents: &[u8]) -> Result<Vec<u8>> {
    let Some((mut start, end)) = marker_range(contents)? else {
        return Ok(contents.to_vec());
    };
    if start > 0 && contents[start - 1] == b'\n' {
        start -= 1;
    }
    let mut updated = Vec::with_capacity(contents.len() - (end - start));
    updated.extend_from_slice(&contents[..start]);
    updated.extend_from_slice(&contents[end..]);
    if yaml_has_only_comments(&updated) {
        if !updated.is_empty() && !updated.ends_with(b"\n") {
            updated.push(b'\n');
        }
        updated.extend_from_slice(b"[]\n");
    }
    Ok(updated)
}

fn empty_sequence_range(contents: &[u8]) -> Option<(usize, usize)> {
    let text = std::str::from_utf8(contents).ok()?;
    let mut offset = 0;
    let mut found = None;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            offset += line.len();
            continue;
        }
        if trimmed != "[]" || found.is_some() {
            return None;
        }
        found = Some((offset, offset + line.len()));
        offset += line.len();
    }
    found
}

fn yaml_has_only_comments(contents: &[u8]) -> bool {
    std::str::from_utf8(contents).is_ok_and(|text| {
        text.lines()
            .all(|line| line.trim().is_empty() || line.trim().starts_with('#'))
    })
}

fn managed_block(enabled: bool) -> Vec<u8> {
    format!(
        "{}\n- id: patronus-security\n  disabled: {}\n{}\n",
        String::from_utf8_lossy(BEGIN),
        !enabled,
        String::from_utf8_lossy(END)
    )
    .into_bytes()
}

fn validate_markers(contents: &[u8]) -> Result<()> {
    marker_range(contents).map(|_| ())
}

fn marker_range(contents: &[u8]) -> Result<Option<(usize, usize)>> {
    let begins = occurrences(contents, BEGIN);
    let ends = occurrences(contents, END);
    match (begins.as_slice(), ends.as_slice()) {
        ([], []) => Ok(None),
        ([start], [end]) if start < end && at_line_start(contents, *start) => {
            let after_marker = end + END.len();
            let block_end = if contents.get(after_marker) == Some(&b'\n') {
                after_marker + 1
            } else if after_marker == contents.len() {
                after_marker
            } else {
                return Err(malformed_markers());
            };
            if !at_line_start(contents, *end) {
                return Err(malformed_markers());
            }
            Ok(Some((*start, block_end)))
        }
        _ => Err(malformed_markers()),
    }
}

fn occurrences(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    haystack
        .windows(needle.len())
        .enumerate()
        .filter_map(|(index, value)| (value == needle).then_some(index))
        .collect()
}

fn at_line_start(contents: &[u8], index: usize) -> bool {
    index == 0 || contents.get(index.wrapping_sub(1)) == Some(&b'\n')
}

fn malformed_markers() -> ScannerError {
    integration_error("DeepSeek patch contains malformed or duplicate Patronus markers")
}

fn integration_error(message: impl Into<String>) -> ScannerError {
    ScannerError::Integration(message.into())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use crate::cli::{IntegrationHost, IntegrationScope};

    use super::*;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn enable_disable_and_remove_preserve_surrounding_bytes() {
        let original = b"before: true\nafter: true";
        let disabled = set_enabled(original, false).unwrap();
        assert!(disabled
            .windows(b"disabled: true".len())
            .any(|window| window == b"disabled: true"));

        let enabled = set_enabled(&disabled, true).unwrap();
        assert_eq!(occurrences(&enabled, BEGIN).len(), 1);
        assert!(enabled
            .windows(b"disabled: false".len())
            .any(|window| window == b"disabled: false"));
        assert_eq!(remove_block(&enabled).unwrap(), original);
    }

    #[test]
    fn empty_patch_round_trips() {
        let installed = set_enabled(b"", true).unwrap();
        assert_eq!(remove_block(&installed).unwrap(), b"[]\n");
    }

    #[test]
    fn harness_empty_sequence_becomes_one_valid_managed_sequence() {
        let installed = set_enabled(b"[]\n", true).unwrap();
        assert!(!installed.starts_with(b"[]"));
        assert_eq!(occurrences(&installed, BEGIN).len(), 1);
        assert_eq!(remove_block(&installed).unwrap(), b"[]\n");
    }

    #[test]
    fn harness_header_and_empty_sequence_round_trip() {
        let original = b"# profile patch\n# keep this comment\n[]\n";
        let installed = set_enabled(original, true).unwrap();
        assert!(installed.starts_with(b"# profile patch\n# keep this comment\n"));
        assert!(!installed.windows(3).any(|window| window == b"[]\n"));
        assert_eq!(remove_block(&installed).unwrap(), original);
    }

    #[test]
    fn malformed_and_duplicate_markers_are_rejected() {
        assert!(set_enabled(BEGIN, true).is_err());
        let duplicate = [managed_block(true), managed_block(false)].concat();
        assert!(remove_block(&duplicate).is_err());
    }

    #[test]
    fn parses_only_one_effective_top_level_patronus_row() {
        assert!(!effective_disabled(
            b"- id: patronus-security\n  name: '@patronus/deepseek-security'\n"
        )
        .unwrap());
        assert!(!effective_disabled(
            b"# == bundle\n- id: patronus-security\n  config:\n    disabled: true\n  disabled: false\n"
        )
        .unwrap());
        assert!(effective_disabled(
            b"- id: other\n  disabled: !!js process.platform === 'win32'\n- id: patronus-security\n  disabled: true\n"
        )
        .unwrap());
        assert!(effective_disabled(
            b"- id: patronus-security\n  disabled: true\n- id: patronus-security\n  disabled: false\n"
        )
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn new_install_verification_failure_removes_the_partial_package() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let log = temp.path().join("calls");
        let fake = temp.path().join("dsh");
        std::fs::write(
            &fake,
            format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n", log.display()),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&fake).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&fake, permissions).unwrap();

        let error = rollback_new_install(&fake, "headless", false, integration_error("failed"))
            .unwrap_err();
        assert!(error.to_string().contains("failed"));
        assert_eq!(
            std::fs::read_to_string(log).unwrap(),
            "plugin --profile headless remove @patronus/deepseek-security\n"
        );
    }

    #[test]
    fn profile_validation_blocks_path_traversal() {
        for invalid in ["", ".", "..", "node_modules", "../headless", "a/b", "a\\b"] {
            assert!(validate_profile(invalid).is_err(), "accepted {invalid:?}");
        }
        for valid in ["headless", "team-1", "team.prod", "team_dev", "team space"] {
            assert!(validate_profile(valid).is_ok(), "rejected {valid:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_preserves_patch_changes_made_by_dsh() {
        use std::os::unix::fs::PermissionsExt;

        let _guard = ENV_LOCK.lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let package = temp.path().join("plugin.tgz");
        std::fs::write(&package, b"package").unwrap();
        let fake = temp.path().join("dsh");
        std::fs::write(
            &fake,
            "#!/bin/sh\nif [ \"$1\" = --profile ]; then if [ \"$PATRONUS_DSH_FORCE_DISABLED\" = true ] || grep -q 'disabled: true' \"$DSH_HOME/profiles/$2/cordis.patch.yml\"; then state=true; else state=false; fi; printf '%s\\n' '- id: patronus-security' \"  disabled: $state\"; exit 0; fi\nmkdir -p \"$DSH_HOME/profiles/$3\"\nif [ \"$4\" = add ]; then printf 'host: added\\n' > \"$DSH_HOME/profiles/$3/cordis.patch.yml\"; printf '{\"dependencies\":{\"@patronus/deepseek-security\":\"file:test\"},\"dsh\":{\"profile\":{\"bundles\":[\"@patronus/deepseek-security\"]}}}' > \"$DSH_HOME/profiles/$3/package.json\"; else printf 'host: removed\\n' > \"$DSH_HOME/profiles/$3/cordis.patch.yml\"; printf '{\"dependencies\":{},\"dsh\":{\"profile\":{\"bundles\":[]}}}' > \"$DSH_HOME/profiles/$3/package.json\"; fi\n",
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&fake).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&fake, permissions).unwrap();
        unsafe {
            std::env::set_var("DSH_HOME", &home);
            std::env::set_var("PATRONUS_DSH_BIN", &fake);
        }
        let args = |action, source| IntegrationArgs {
            host: IntegrationHost::Deepseek,
            action,
            source,
            scope: IntegrationScope::User,
            profile: Some("headless".into()),
            keep_data: false,
        };

        execute(args(IntegrationAction::Install, Some(package))).unwrap();
        let patch = home.join("profiles/headless/cordis.patch.yml");
        let installed = std::fs::read_to_string(&patch).unwrap();
        assert!(installed.contains("host: added"));
        assert!(installed.contains("disabled: false"));
        execute(args(IntegrationAction::Disable, None)).unwrap();
        assert!(std::fs::read_to_string(&patch)
            .unwrap()
            .contains("disabled: true"));
        unsafe {
            std::env::set_var("PATRONUS_DSH_FORCE_DISABLED", "true");
        }
        assert!(execute(args(IntegrationAction::Enable, None)).is_err());
        assert!(std::fs::read_to_string(&patch)
            .unwrap()
            .contains("disabled: true"));
        unsafe {
            std::env::remove_var("PATRONUS_DSH_FORCE_DISABLED");
        }
        execute(args(IntegrationAction::Enable, None)).unwrap();
        execute(args(IntegrationAction::Uninstall, None)).unwrap();
        assert_eq!(std::fs::read_to_string(patch).unwrap(), "host: removed\n");
        unsafe {
            std::env::remove_var("DSH_HOME");
            std::env::remove_var("PATRONUS_DSH_BIN");
            std::env::remove_var("PATRONUS_DSH_FORCE_DISABLED");
        }
    }
}
