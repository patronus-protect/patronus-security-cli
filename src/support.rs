use std::collections::HashSet;
use std::io::{IsTerminal, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zip::write::SimpleFileOptions;

use crate::cli::SupportArgs;
use crate::error::{IoContext, Result, ScannerError};

#[derive(Debug, Serialize)]
struct SupportManifest<'a> {
    schema: &'static str,
    scanner_version: &'static str,
    ark_version: &'static str,
    message: Option<&'a str>,
    entries: &'a [BundleEntry],
    redactions: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BundleEntry {
    logical_path: String,
    kind: String,
    size_bytes: u64,
    blake3: String,
}

struct BundleItem {
    entry: BundleEntry,
    bytes: Vec<u8>,
}

pub fn execute(args: SupportArgs) -> Result<()> {
    let run_dir = if let Some(run) = args.run.as_deref() {
        validate_run(run)?
    } else if args.latest {
        latest_run(Path::new("."))?
    } else {
        return Err(ScannerError::Support(
            "select exactly one of --run or --latest".into(),
        ));
    };
    let config_text = std::fs::read_to_string(run_dir.join("effective-config.toml"))
        .at(run_dir.join("effective-config.toml"))?;
    let config: crate::config::Config = toml::from_str(&config_text)
        .map_err(|error| ScannerError::Support(format!("invalid effective config: {error}")))?;
    let manifest_bytes =
        std::fs::read(run_dir.join("manifest.json")).at(run_dir.join("manifest.json"))?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| ScannerError::Support(format!("invalid run manifest: {error}")))?;
    let scan_root = manifest
        .get("scan_root")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| ScannerError::Support("run manifest has no scan_root".into()))?;

    let excluded = args
        .exclude
        .iter()
        .map(|path| logical(path))
        .collect::<Result<HashSet<_>>>()?;
    let mut items = Vec::new();
    for name in &config.support.default_artifacts {
        if excluded.contains(name) {
            continue;
        }
        let path = run_dir.join(name);
        if !path.is_file() {
            continue;
        }
        let bytes = sanitized_artifact(name, &path)?;
        items.push(item(name.clone(), "generated_artifact", bytes));
    }
    for relative in &args.include {
        let logical_path = logical(relative)?;
        if excluded.contains(&logical_path) {
            continue;
        }
        let path = scan_root.join(relative);
        let metadata = std::fs::symlink_metadata(&path).at(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ScannerError::Support(format!(
                "included source must be a regular non-symlink file: {logical_path}"
            )));
        }
        let canonical = std::fs::canonicalize(&path).at(&path)?;
        let root = std::fs::canonicalize(&scan_root).at(&scan_root)?;
        if !canonical.starts_with(&root) {
            return Err(ScannerError::Support(format!(
                "included source escapes scan root: {logical_path}"
            )));
        }
        if metadata.len() > config.scan.max_file_bytes {
            return Err(ScannerError::Support(format!(
                "included source exceeds per-file limit: {logical_path}"
            )));
        }
        items.push(item(
            format!("source/{logical_path}"),
            "user_source_file",
            std::fs::read(&canonical).at(&canonical)?,
        ));
    }
    if let Some(message) = args.message.as_deref() {
        items.push(item(
            "message.txt".into(),
            "user_message",
            sanitize(message, 8192).into_bytes(),
        ));
    }
    let manifest_entries = items
        .iter()
        .map(|item| item.entry.clone())
        .collect::<Vec<_>>();
    let manifest = SupportManifest {
        schema: "patronus.security-scanner.support-bundle.v1",
        scanner_version: crate::VERSION,
        ark_version: crate::ARK_VERSION,
        message: args.message.as_deref(),
        entries: &manifest_entries,
        redactions: vec![
            "absolute scan_root removed",
            "raw evidence text removed",
            "configured secret-like fields redacted",
        ],
    };
    let support_manifest = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| ScannerError::Support(error.to_string()))?;
    items.push(item(
        "support-manifest.json".into(),
        "generated_manifest",
        support_manifest,
    ));
    let estimated: u64 = items.iter().map(|item| item.entry.size_bytes).sum();
    if estimated > config.support.max_bundle_bytes {
        return Err(ScannerError::Support(format!(
            "bundle members total {estimated} bytes, above configured limit {}",
            config.support.max_bundle_bytes
        )));
    }
    let bundle_path = args
        .bundle_out
        .unwrap_or_else(|| run_dir.join("support-bundle.zip"));
    write_bundle(&bundle_path, &items)?;
    let size = std::fs::metadata(&bundle_path).at(&bundle_path)?.len();
    if size > config.support.max_bundle_bytes {
        return Err(ScannerError::Support(format!(
            "archive is {size} bytes, above configured limit {}",
            config.support.max_bundle_bytes
        )));
    }
    preview(&config.support.endpoint, &bundle_path, &items, size);
    if args.dry_run {
        println!("Dry run complete; no network request was made.");
        return Ok(());
    }
    if config.support.endpoint.is_empty() {
        return Err(ScannerError::Support(
            "support upload is disabled because support.endpoint is empty".into(),
        ));
    }
    if !config.support.endpoint.starts_with("https://") {
        return Err(ScannerError::Support(
            "support endpoint must use HTTPS".into(),
        ));
    }
    if !args.yes {
        if !std::io::stdin().is_terminal() {
            return Err(ScannerError::Support(
                "non-interactive upload requires --yes".into(),
            ));
        }
        eprint!("Upload exactly this bundle? Type 'yes' to continue: ");
        std::io::stderr()
            .flush()
            .map_err(|error| ScannerError::Support(error.to_string()))?;
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .map_err(|error| ScannerError::Support(error.to_string()))?;
        if answer.trim() != "yes" {
            return Err(ScannerError::Support("upload cancelled".into()));
        }
    }
    upload(&config.support.endpoint, &bundle_path)
}

fn validate_run(path: &Path) -> Result<PathBuf> {
    let canonical = std::fs::canonicalize(path).at(path)?;
    if !canonical.join("COMPLETE").is_file() {
        return Err(ScannerError::Support(
            "selected run is incomplete (missing COMPLETE)".into(),
        ));
    }
    Ok(canonical)
}

fn latest_run(_start: &Path) -> Result<PathBuf> {
    let root = crate::config::user_root()?.join("output");
    let mut runs = std::fs::read_dir(&root)
        .at(&root)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.join("COMPLETE").is_file())
        .collect::<Vec<_>>();
    runs.sort();
    runs.pop().ok_or_else(|| {
        ScannerError::Support(format!("no completed run found under {}", root.display()))
    })
}

fn logical(path: &Path) -> Result<String> {
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ScannerError::Support(format!(
            "path must contain only relative normal components: {}",
            path.display()
        )));
    }
    let value = path
        .components()
        .map(|part| part.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    if value.is_empty() {
        return Err(ScannerError::Support("empty relative path".into()));
    }
    Ok(value)
}

fn sanitized_artifact(name: &str, path: &Path) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path).at(path)?;
    if name == "manifest.json" {
        let mut value: Value = serde_json::from_slice(&bytes)
            .map_err(|error| ScannerError::Support(error.to_string()))?;
        if let Some(object) = value.as_object_mut() {
            object.remove("scan_root");
        }
        return serde_json::to_vec_pretty(&value)
            .map_err(|error| ScannerError::Support(error.to_string()));
    }
    if name == "classifications.jsonl" {
        let mut output = Vec::new();
        for line in bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let mut value: Value = serde_json::from_slice(line)
                .map_err(|error| ScannerError::Support(error.to_string()))?;
            if let Some(object) = value.as_object_mut() {
                object.insert("evidence".into(), Value::Array(Vec::new()));
            }
            serde_json::to_writer(&mut output, &value)
                .map_err(|error| ScannerError::Support(error.to_string()))?;
            output.push(b'\n');
        }
        return Ok(output);
    }
    Ok(bytes)
}

fn item(logical_path: String, kind: &str, bytes: Vec<u8>) -> BundleItem {
    let entry = BundleEntry {
        logical_path,
        kind: kind.into(),
        size_bytes: bytes.len() as u64,
        blake3: format!("blake3:{}", blake3::hash(&bytes).to_hex()),
    };
    BundleItem { entry, bytes }
}

fn write_bundle(path: &Path, items: &[BundleItem]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).at(parent)?;
    }
    let file = std::fs::File::create(path).at(path)?;
    let mut archive = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o600);
    for item in items {
        archive
            .start_file(&item.entry.logical_path, options)
            .map_err(|error| ScannerError::Support(error.to_string()))?;
        archive
            .write_all(&item.bytes)
            .map_err(|error| ScannerError::Support(error.to_string()))?;
    }
    archive
        .finish()
        .map_err(|error| ScannerError::Support(error.to_string()))?;
    Ok(())
}

fn preview(endpoint: &str, path: &Path, items: &[BundleItem], size: u64) {
    let host = endpoint
        .strip_prefix("https://")
        .and_then(|value| value.split('/').next())
        .unwrap_or("<disabled>");
    println!(
        "Support bundle preview\nEndpoint host: {host}\nBundle: {}\nArchive size: {size} bytes",
        path.display()
    );
    for item in items {
        let warning = if item.entry.kind == "user_source_file" {
            " WARNING: explicitly included source"
        } else {
            ""
        };
        println!(
            "- {} [{}] {} bytes {}{}",
            item.entry.logical_path,
            item.entry.kind,
            item.entry.size_bytes,
            item.entry.blake3,
            warning
        );
    }
    println!("Redactions: absolute scan root, raw evidence text, secret-like config fields");
}

fn upload(endpoint: &str, path: &Path) -> Result<()> {
    let bytes = std::fs::read(path).at(path)?;
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(30))
        .timeout_write(Duration::from_secs(30))
        .build();
    let mut request = agent.post(endpoint).set("Content-Type", "application/zip");
    if let Ok(token) = std::env::var("PATRONUS_SUPPORT_TOKEN") {
        request = request.set("Authorization", &format!("Bearer {token}"));
    }
    let response = request
        .send_bytes(&bytes)
        .map_err(|error| ScannerError::Support(format!("upload failed: {error}")))?;
    let value: Value = response
        .into_json()
        .map_err(|error| ScannerError::Support(format!("invalid server response: {error}")))?;
    let case_id = value
        .get("case_id")
        .and_then(Value::as_str)
        .ok_or_else(|| ScannerError::Support("server response has no case_id".into()))?;
    println!("Support case: {}", sanitize(case_id, 256));
    println!("Sent bundle retained at: {}", path.display());
    Ok(())
}

fn sanitize(value: &str, max: usize) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_control() || matches!(ch, '\n' | '\t'))
        .take(max)
        .collect()
}
