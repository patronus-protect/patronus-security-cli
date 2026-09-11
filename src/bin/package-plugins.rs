use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use zip::write::SimpleFileOptions;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().nth(1).as_deref() == Some("--verify-version") {
        let expected = std::env::args().nth(2).ok_or("missing release version")?;
        verify_versions(&expected)?;
        return Ok(());
    }
    let mut arguments = std::env::args_os().skip(1);
    if std::env::args().nth(1).as_deref() == Some("--checksum") {
        for path in std::env::args_os().skip(2) {
            print_checksum(Path::new(&path))?;
        }
        return Ok(());
    }
    let binary = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("usage: package-plugins BINARY TARGET OUT_DIR [--include-plugins]")?;
    let target = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or("missing target")?;
    let out = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("missing output directory")?;
    let plugin_option = arguments.next();
    let include_plugins = plugin_option
        .as_ref()
        .is_some_and(|value| value == "--include-plugins");
    if plugin_option.is_some() && !include_plugins {
        return Err("unknown option; expected --include-plugins".into());
    }
    if arguments.next().is_some() || !binary.is_file() {
        return Err("invalid arguments or missing binary".into());
    }
    std::fs::create_dir_all(&out)?;
    let executable = if target.contains("windows") {
        "patronus-security-scanner.exe"
    } else {
        "patronus-security-scanner"
    };
    let cli_archive = out.join(format!(
        "patronus-security-scanner-{}-{target}.zip",
        env!("CARGO_PKG_VERSION")
    ));
    let mut archive = zip::ZipWriter::new(File::create(&cli_archive)?);
    add_file(&mut archive, &binary, Path::new(executable), true)?;
    for name in ["LICENSE", "THIRD_PARTY_NOTICES.md"] {
        add_file(&mut archive, Path::new(name), Path::new(name), false)?;
    }
    add_file(
        &mut archive,
        Path::new("INSTALL.md"),
        Path::new("INSTALL.md"),
        false,
    )?;
    for license in ["Inter-OFL.txt", "Manrope-OFL.txt"] {
        add_file(
            &mut archive,
            &Path::new("src/dashboard/assets").join(license),
            &Path::new("licenses").join(license),
            false,
        )?;
    }
    archive.finish()?;
    print_checksum(&cli_archive)?;

    if include_plugins {
        for plugin in ["codex", "claude"] {
            let archive_name = format!(
                "patronus-security-{plugin}-{}.zip",
                env!("CARGO_PKG_VERSION")
            );
            let archive_path = out.join(archive_name);
            let mut archive = zip::ZipWriter::new(File::create(&archive_path)?);
            let marketplace = match plugin {
                "codex" => Path::new(".agents/plugins/marketplace.json"),
                "claude" => Path::new(".claude-plugin/marketplace.json"),
                _ => unreachable!(),
            };
            add_file(&mut archive, marketplace, marketplace, false)?;
            let files: &[&str] = match plugin {
                "codex" => &[
                    ".codex-plugin/plugin.json",
                    ".mcp.json",
                    "README.md",
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
                    "assets/icon.png",
                    "hooks/hooks.json",
                    "scripts/patronus.mjs",
                    "skills/patronus-setup/SKILL.md",
                    "skills/runtime/SKILL.md",
                    "skills/scan/SKILL.md",
                ],
                _ => unreachable!(),
            };
            for relative in files {
                let path = Path::new("plugins").join(plugin).join(relative);
                add_file(&mut archive, &path, &path, false)?;
            }
            for name in ["LICENSE", "THIRD_PARTY_NOTICES.md"] {
                add_file(&mut archive, Path::new(name), Path::new(name), false)?;
            }
            archive.finish()?;
            print_checksum(&archive_path)?;
        }
    }
    Ok(())
}

fn verify_versions(expected: &str) -> Result<(), Box<dyn std::error::Error>> {
    if expected != env!("CARGO_PKG_VERSION") {
        return Err(format!(
            "release version {expected} does not match Cargo version {}",
            env!("CARGO_PKG_VERSION")
        )
        .into());
    }
    for path in [
        "plugins/codex/.codex-plugin/plugin.json",
        "plugins/claude/.claude-plugin/plugin.json",
        ".claude-plugin/marketplace.json",
        "plugins/deepseek/package.json",
        "plugins/native/package.json",
    ] {
        let value: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
        let version = value["version"]
            .as_str()
            .or_else(|| value["plugins"].get(0)?.get("version")?.as_str())
            .ok_or_else(|| format!("missing version in {path}"))?;
        if version != expected {
            return Err(
                format!("{path} version {version} does not match release {expected}").into(),
            );
        }
    }
    Ok(())
}

fn print_checksum(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let digest = ring::digest::digest(&ring::digest::SHA256, &std::fs::read(path)?);
    let checksum: String = digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    std::fs::write(
        format!("{}.sha256", path.display()),
        format!("{checksum}\n"),
    )?;

    std::fs::write(
        format!("{}.blake3", path.display()),
        format!("{}\n", blake3::hash(&std::fs::read(path)?).to_hex()),
    )?;
    println!(
        "{}  {}",
        blake3::hash(&std::fs::read(path)?).to_hex(),
        path.display()
    );
    Ok(())
}

fn add_file(
    archive: &mut zip::ZipWriter<File>,
    source: &Path,
    destination: &Path,
    executable: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let permissions = if executable { 0o755 } else { 0o644 };
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(permissions);
    archive.start_file(destination.to_string_lossy().replace('\\', "/"), options)?;
    let mut bytes = Vec::new();
    File::open(source)?.read_to_end(&mut bytes)?;
    archive.write_all(&bytes)?;
    Ok(())
}
