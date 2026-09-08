use patronus_security_scanner::config::{Config, DEFAULTS};
use patronus_security_scanner::discovery::discover;
use patronus_security_scanner::target::{ScanTarget, TargetKind};

#[test]
fn hard_exclusions_and_explicit_file_semantics_are_enforced() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join(".git")).unwrap();
    std::fs::write(temp.path().join(".git/config"), "untrusted").unwrap();
    std::fs::write(temp.path().join("visible.txt"), "visible").unwrap();
    std::fs::write(temp.path().join("ignored.txt"), "ignored").unwrap();
    std::fs::write(temp.path().join(".gitignore"), "ignored.txt\n").unwrap();
    let output = temp.path().join(".patronus-security-scanner/output");
    std::fs::create_dir_all(&output).unwrap();
    std::fs::write(output.join("old.json"), "old").unwrap();
    let config: Config = toml::from_str(DEFAULTS).unwrap();

    let directory = ScanTarget::resolve(TargetKind::Directory, temp.path()).unwrap();
    let discovered = discover(&directory, &config, &[], &output).unwrap();
    let eligible = discovered
        .files
        .iter()
        .filter(|file| file.eligible)
        .map(|file| file.path.as_str())
        .collect::<Vec<_>>();
    assert!(eligible.contains(&"visible.txt"));
    assert!(!eligible.contains(&"ignored.txt"));
    assert!(!eligible.iter().any(|path| path.starts_with(".git/")));
    assert!(!eligible.iter().any(|path| path.contains("old.json")));

    let explicit = ScanTarget::resolve(TargetKind::File, &temp.path().join("ignored.txt")).unwrap();
    let discovered = discover(&explicit, &config, &[], &output).unwrap();
    assert_eq!(discovered.eligible_files, 1);
}

#[test]
fn repository_paths_cannot_impersonate_installed_patronus_plugins() {
    let temp = tempfile::tempdir().unwrap();
    let generated = [
        "plugins/native/dist/patronus.mjs",
        "plugins/codex/scripts/patronus.mjs",
        "plugins/claude/scripts/patronus.mjs",
        "plugins/deepseek/dist/index.js",
        "plugins/deepseek/patronus-deepseek-security-0.1.0.tgz",
    ];
    for path in generated {
        let path = temp.path().join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "generated").unwrap();
    }
    for path in [
        "plugins/codex/scripts/other.mjs",
        "plugins/deepseek/dist/other.js",
        "patronus/plugin/patronus.mjs",
    ] {
        let path = temp.path().join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "must remain eligible").unwrap();
    }

    let config: Config = toml::from_str(DEFAULTS).unwrap();
    let output = temp.path().join(".patronus-security-scanner/output");
    let target = ScanTarget::resolve(TargetKind::Directory, temp.path()).unwrap();
    let discovered = discover(&target, &config, &[], &output).unwrap();

    for path in generated.into_iter().chain([
        "plugins/codex/scripts/other.mjs",
        "plugins/deepseek/dist/other.js",
        "patronus/plugin/patronus.mjs",
    ]) {
        assert!(
            discovered
                .files
                .iter()
                .any(|file| file.path == path && file.eligible),
            "{path} must not impersonate an installed plugin root"
        );
    }

    let explicit = ScanTarget::resolve(
        TargetKind::File,
        &temp.path().join("plugins/native/dist/patronus.mjs"),
    )
    .unwrap();
    let explicit = discover(&explicit, &config, &[], &output).unwrap();
    assert_eq!(explicit.eligible_files, 1);
}
