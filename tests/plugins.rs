use serde_json::Value;

#[test]
fn plugin_manifests_and_skills_are_minimal_and_consistent() {
    let codex: Value =
        serde_json::from_str(include_str!("../plugins/codex/.codex-plugin/plugin.json")).unwrap();
    let claude: Value =
        serde_json::from_str(include_str!("../plugins/claude/.claude-plugin/plugin.json")).unwrap();
    assert_eq!(codex["name"], "patronus-security");
    assert_eq!(claude["name"], "patronus-security");
    assert_eq!(codex["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(claude["version"], env!("CARGO_PKG_VERSION"));
    for skill in [
        include_str!("../plugins/codex/skills/patronus-security-scan/SKILL.md"),
        include_str!("../plugins/claude/skills/scan/SKILL.md"),
    ] {
        assert!(!skill.contains("TODO"));
        assert!(skill.contains("support-us"));
        assert!(skill.contains("INCOMPLETE"));
        assert!(!skill.contains("curl"));
        assert!(skill.contains("`PATH`"));
        assert!(skill.contains("config print --format json"));
        assert!(skill.contains("hybrid"));
        assert!(!skill.contains("webmcp"));
        assert!(skill.contains("fall"));
        assert!(!skill.contains("bundled executable"));
    }
}

#[test]
fn local_marketplaces_expose_the_matching_plugins() {
    let codex: Value =
        serde_json::from_str(include_str!("../.agents/plugins/marketplace.json")).unwrap();
    let claude: Value =
        serde_json::from_str(include_str!("../.claude-plugin/marketplace.json")).unwrap();

    assert_eq!(codex["name"], "patronus-local");
    assert_eq!(codex["plugins"][0]["name"], "patronus-security");
    assert_eq!(codex["plugins"][0]["source"]["path"], "./plugins/codex");
    assert_eq!(claude["name"], "patronus-local");
    assert_eq!(claude["plugins"][0]["name"], "patronus-security");
    assert_eq!(claude["plugins"][0]["source"], "./plugins/claude");
}

#[test]
fn release_archives_are_installable_marketplace_roots_without_test_artifacts() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("scanner");
    std::fs::write(&binary, b"binary").unwrap();
    let output = temp.path().join("dist");
    assert_cmd::Command::cargo_bin("package-plugins")
        .unwrap()
        .arg(&binary)
        .args(["test-target"])
        .arg(&output)
        .arg("--include-plugins")
        .assert()
        .success();

    let cli = std::fs::File::open(output.join(format!(
        "patronus-security-scanner-{}-test-target.zip",
        env!("CARGO_PKG_VERSION")
    )))
    .unwrap();
    let mut cli = zip::ZipArchive::new(cli).unwrap();
    let cli_names = (0..cli.len())
        .map(|index| cli.by_index(index).unwrap().name().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        cli_names,
        [
            "patronus-security-scanner",
            "LICENSE",
            "THIRD_PARTY_NOTICES.md",
            "INSTALL.md",
            "licenses/Inter-OFL.txt",
            "licenses/Manrope-OFL.txt",
        ]
    );

    for (host, marketplace) in [
        ("codex", ".agents/plugins/marketplace.json"),
        ("claude", ".claude-plugin/marketplace.json"),
    ] {
        let archive = std::fs::File::open(output.join(format!(
            "patronus-security-{host}-{}.zip",
            env!("CARGO_PKG_VERSION")
        )))
        .unwrap();
        let mut archive = zip::ZipArchive::new(archive).unwrap();
        let names = (0..archive.len())
            .map(|index| archive.by_index(index).unwrap().name().to_owned())
            .collect::<Vec<_>>();
        let runtime_files: &[&str] = match host {
            "codex" => &[
                ".codex-plugin/plugin.json",
                ".mcp.json",
                "README.md",
                "INSTALL.md",
                "assets/icon.png",
                "hooks/hooks.json",
                "scripts/patronus.mjs",
                "skills/patronus-runtime/SKILL.md",
                "skills/patronus-security-scan/SKILL.md",
                "skills/patronus-security-scan/agents/openai.yaml",
                "skills/patronus-setup/SKILL.md",
            ],
            "claude" => &[
                ".claude-plugin/plugin.json",
                ".mcp.json",
                "README.md",
                "INSTALL.md",
                "assets/icon.png",
                "hooks/hooks.json",
                "scripts/patronus.mjs",
                "skills/patronus-setup/SKILL.md",
                "skills/runtime/SKILL.md",
                "skills/scan/SKILL.md",
            ],
            _ => unreachable!(),
        };
        let expected = std::iter::once(marketplace.to_owned())
            .chain(
                runtime_files
                    .iter()
                    .map(|path| format!("plugins/{host}/{path}")),
            )
            .chain(["LICENSE".into(), "THIRD_PARTY_NOTICES.md".into()])
            .collect::<Vec<String>>();
        assert_eq!(names, expected);
    }
}
