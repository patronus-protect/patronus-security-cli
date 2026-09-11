use std::io::Read;
use std::path::{Path, PathBuf};

use clap::Parser;
use patronus_security_scanner::ark::{ChunkInput, ContentAnalyzer};
use patronus_security_scanner::chunk::chunk_content;
use patronus_security_scanner::cli::{
    AssetsCommand, Cli, Command, ConfigCommand, ConfigFormat, OutputFormat, ProtocolCommand,
};
use patronus_security_scanner::config::Config;
use patronus_security_scanner::content::read_decode;
use patronus_security_scanner::discovery::discover;
use patronus_security_scanner::error::{Result, ScannerError};
use patronus_security_scanner::output::{output_root, RunOutput};
use patronus_security_scanner::progress::{initial_phase, ProgressTracker};
use patronus_security_scanner::report::{build_report, exit_code, terminal_summary, ReportBuilder};
use patronus_security_scanner::target::{display_path, ScanTarget, TargetKind};

fn main() {
    let cli = Cli::parse();
    match execute(cli) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("error: {error}");
            let code = match error {
                ScannerError::Config { .. } | ScannerError::Target { .. } => 2,
                ScannerError::Support(_) => 5,
                ScannerError::Integration(_) => 6,
                _ => 4,
            };
            std::process::exit(code);
        }
    }
}

fn execute(cli: Cli) -> Result<i32> {
    match cli.command {
        Command::Onboarding {
            status,
            format,
            open,
            check,
        } => {
            if check {
                return patronus_security_scanner::onboarding::check_command(format);
            }
            if open {
                patronus_security_scanner::onboarding::open_terminal()?;
                return Ok(0);
            }
            patronus_security_scanner::onboarding::execute(status, format)
        }
        Command::Scan {
            target: patronus_security_scanner::cli::ScanTarget::Url(args),
        } => patronus_security_scanner::remote_scan::execute("url", args),
        Command::Scan {
            target: patronus_security_scanner::cli::ScanTarget::Mcp(args),
        } => patronus_security_scanner::remote_scan::execute("mcp", args),
        Command::Scan {
            target: patronus_security_scanner::cli::ScanTarget::File { path, options },
        } if options.anonymous_api => {
            patronus_security_scanner::remote_scan::execute_file(&path, options)
        }
        Command::Maintenance { command } => {
            patronus_security_scanner::maintenance::execute(command)?;
            Ok(0)
        }
        Command::Dashboard { port } => {
            patronus_security_scanner::dashboard_server::serve(port)?;
            Ok(0)
        }
        Command::Policy { command } => patronus_security_scanner::local_settings::policy(command),
        Command::Auth { command } => {
            patronus_security_scanner::auth::execute(command)?;
            Ok(0)
        }
        Command::Serve {
            config, state_dir, ..
        } => {
            let config = Config::load(config.as_deref(), None)?;
            patronus_security_scanner::runtime::service::serve(config, state_dir.as_deref())
                .map_err(ScannerError::Output)?;
            Ok(0)
        }
        Command::Scan { target } => {
            let (kind, path, options) = target.into_parts();
            scan(kind, &path, options)
        }
        Command::Config { command } => config_command(command),
        Command::Plugins { command } => {
            patronus_security_scanner::plugin_settings::execute(command)?;
            Ok(0)
        }
        Command::Assets { command } => assets_command(command),
        Command::Protocol { command } => protocol_command(command),
        Command::Integration(args) => {
            patronus_security_scanner::integrations::execute(args)?;
            Ok(0)
        }
        Command::SupportUs(args) => patronus_security_scanner::support::execute(args).map(|()| 0),
        Command::Version => {
            println!(
                "patronus-security-scanner {} (patronus-ark {})",
                patronus_security_scanner::VERSION,
                patronus_security_scanner::ARK_VERSION
            );
            Ok(0)
        }
    }
}

fn protocol_command(command: ProtocolCommand) -> Result<i32> {
    match command {
        ProtocolCommand::Append { root, journal_only } => {
            let root = root.unwrap_or(patronus_security_scanner::config::user_root()?);
            let mut input = String::new();
            std::io::stdin()
                .read_to_string(&mut input)
                .map_err(|error| ScannerError::Output(error.to_string()))?;
            let event = serde_json::from_str(&input).map_err(|error| {
                ScannerError::Output(format!("invalid protocol event: {error}"))
            })?;
            let report_root = if root == patronus_security_scanner::config::user_root()?
                || root
                    .file_name()
                    .is_some_and(|name| name == ".patronus-security-scanner")
            {
                root
            } else {
                root.join(".patronus-security-scanner")
            };
            let path = patronus_security_scanner::dashboard::persist_protocol_event(
                &report_root,
                &event,
                !journal_only,
            )?;
            println!("{}", path.display());
            Ok(0)
        }
        ProtocolCommand::Render { root } => {
            let root = root.unwrap_or(patronus_security_scanner::config::user_root()?);
            let root = if root == patronus_security_scanner::config::user_root()?
                || root
                    .file_name()
                    .is_some_and(|name| name == ".patronus-security-scanner")
            {
                root
            } else {
                root.join(".patronus-security-scanner")
            };
            patronus_security_scanner::dashboard::rebuild_index(&root, &root.join("output"))?;
            println!("{}", root.join("index.html").display());
            Ok(0)
        }
    }
}

fn config_command(command: ConfigCommand) -> Result<i32> {
    match command {
        ConfigCommand::Import { path } => {
            patronus_security_scanner::local_settings::import_config(&path)?;
        }
        ConfigCommand::Init {
            path,
            force,
            provider,
        } => {
            let path = path.unwrap_or_else(default_config_path);
            patronus_security_scanner::config::write_defaults(&path, force, provider)?;
            println!("Wrote {}", path.display());
        }
        ConfigCommand::Print { config, format } => {
            let config = Config::load(config.as_deref(), None)?;
            match format {
                ConfigFormat::Toml => print!("{}", config.redacted_toml()?),
                ConfigFormat::Json => {
                    let value: toml::Value = toml::from_str(&config.redacted_toml()?)
                        .map_err(|error| ScannerError::Output(error.to_string()))?;
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&value)
                            .map_err(|error| ScannerError::Output(error.to_string()))?
                    );
                }
            }
        }
    }
    Ok(0)
}

fn assets_command(command: AssetsCommand) -> Result<i32> {
    match command {
        AssetsCommand::Prepare { config } => {
            let mut config = Config::load(config.as_deref(), None)?;
            patronus_security_scanner::model_assets::prepare(&mut config)?;
            println!("Ark assets are ready for the configured profile.");
        }
    }
    Ok(0)
}

fn default_config_path() -> PathBuf {
    patronus_security_scanner::config::user_root()
        .expect("user home directory is required")
        .join("config.toml")
}

fn scan(
    kind: TargetKind,
    input: &Path,
    options: patronus_security_scanner::cli::ScanOptions,
) -> Result<i32> {
    let target = ScanTarget::resolve(kind, input)?;
    let repo_config =
        (kind == TargetKind::Repo && !options.no_repo_config).then_some(target.root.as_path());
    let mut config = Config::load(options.config.as_deref(), repo_config)?;
    config.apply_scan_options(&options)?;
    if config.output.include_chunk_content || config.output.include_evidence_text {
        eprintln!("warning: sensitive content storage is enabled in output artifacts");
    }
    let output_root = output_root(&target, &config.output.root);
    let output = RunOutput::create(
        &output_root,
        config.output.include_chunk_content,
        config.output.write_progress_events,
    )?;
    output.write_config(&config)?;
    let progress_path = output.progress_path();
    initial_phase(
        config.progress.mode,
        "discovering files",
        progress_path.as_deref(),
    );
    let mut discovery = discover(&target, &config, &options.include, &output_root)?;
    let mut progress = ProgressTracker::new(
        &config.progress,
        discovery.eligible_bytes,
        discovery.eligible_files,
        progress_path,
    );
    progress.phase("preparing Ark/models");
    let mut builder = ReportBuilder::new();
    let mut analyzer = patronus_security_scanner::inference::Inference::new(&config)?;
    let prepared = match analyzer.prepare() {
        Ok(()) => true,
        Err(error) => {
            builder.degraded = true;
            builder.failure(
                &output.run_id,
                None,
                None,
                None,
                "ark_prepare",
                error.to_string(),
            );
            false
        }
    };
    progress.phase("scanning");
    let mut analyzed_files = 0usize;
    let mut analyzed_bytes = 0u64;
    let mut processed_bytes = 0u64;
    let mut completed_files = 0usize;
    let mut skipped_files = discovery.skipped_files;
    if prepared {
        for file in discovery.files.iter_mut().filter(|file| file.eligible) {
            let decoded = match read_decode(
                &file.absolute_path,
                file.size_bytes,
                config.scan.max_file_bytes,
                &target.root,
            )? {
                Ok(decoded) => decoded,
                Err(error) => {
                    file.eligible = false;
                    file.skip_reason = Some(error.to_string().replace(' ', "_"));
                    skipped_files += 1;
                    builder.failure(
                        &output.run_id,
                        Some(&file.path),
                        None,
                        None,
                        "content",
                        error.to_string(),
                    );
                    completed_files += 1;
                    progress.update(
                        processed_bytes,
                        completed_files,
                        builder.chunk_count,
                        skipped_files,
                        builder.failures.len(),
                        false,
                    );
                    continue;
                }
            };
            if !config
                .scan
                .supported_encodings
                .iter()
                .any(|encoding| encoding == decoded.encoding.as_str())
            {
                file.eligible = false;
                file.skip_reason = Some("unsupported_encoding".into());
                skipped_files += 1;
                builder.failure(
                    &output.run_id,
                    Some(&file.path),
                    None,
                    None,
                    "content",
                    format!(
                        "encoding {} is disabled by configuration",
                        decoded.encoding.as_str()
                    ),
                );
                completed_files += 1;
                progress.update(
                    processed_bytes,
                    completed_files,
                    builder.chunk_count,
                    skipped_files,
                    builder.failures.len(),
                    false,
                );
                continue;
            }
            let chunks = chunk_content(&file.path, &decoded, &config.chunking);
            let mut file_analyzed = true;
            for chunk in chunks {
                builder.chunk_count += 1;
                let content = &decoded.text[chunk.decoded_byte_start..chunk.decoded_byte_end];
                output.chunk(&chunk, content)?;
                match analyzer.analyze(ChunkInput {
                    input_tokens: None,
                    run_id: &output.run_id,
                    chunk_id: &chunk.chunk_id,
                    file_id: &chunk.file_id,
                    path: &chunk.path,
                    content,
                }) {
                    Ok(outcome) => {
                        builder.degraded |= outcome.degraded;
                        for message in outcome.failures {
                            builder.failure(
                                &output.run_id,
                                Some(&file.path),
                                Some(&chunk.chunk_id),
                                None,
                                "ark_classification",
                                message,
                            );
                            file_analyzed = false;
                        }
                        for classification in outcome.classifications {
                            output.classification(&classification)?;
                            builder.classification(&classification, &chunk);
                        }
                    }
                    Err(error) => {
                        builder.failure(
                            &output.run_id,
                            Some(&file.path),
                            Some(&chunk.chunk_id),
                            None,
                            "ark_classification",
                            error.to_string(),
                        );
                        file_analyzed = false;
                    }
                }
                progress.update(
                    processed_bytes + chunk.original_byte_end as u64,
                    completed_files,
                    builder.chunk_count,
                    skipped_files,
                    builder.failures.len(),
                    false,
                );
            }
            if file_analyzed {
                analyzed_files += 1;
                analyzed_bytes += file.size_bytes;
            }
            processed_bytes += file.size_bytes;
            completed_files += 1;
            progress.update(
                processed_bytes,
                completed_files,
                builder.chunk_count,
                skipped_files,
                builder.failures.len(),
                false,
            );
        }
    }
    progress.update(
        processed_bytes,
        completed_files,
        builder.chunk_count,
        skipped_files,
        builder.failures.len(),
        true,
    );
    progress.finish();
    progress.phase("writing report");
    for file in &discovery.files {
        output.file(file)?;
    }
    for failure in &builder.failures {
        output.failure(failure)?;
    }
    let report_relative = display_path(&target.root, &output.run_dir.join("report.md"));
    let mut report = build_report(
        output.run_id.clone(),
        target.kind,
        target
            .explicit_file
            .as_ref()
            .unwrap_or(&target.root)
            .to_string_lossy()
            .into_owned(),
        output.started_at(),
        progress.elapsed().as_millis() as u64,
        &discovery.files,
        discovery.eligible_files,
        discovery.eligible_bytes,
        analyzed_files,
        analyzed_bytes,
        config.ark.categories.clone(),
        config.ark.max_level.clone(),
        builder,
        report_relative,
    );
    report.ark_category_levels = config
        .ark
        .categories
        .iter()
        .map(|category| {
            let canonical = if category == "injection" {
                "prompt_injection"
            } else {
                category
            };
            (
                canonical.to_owned(),
                config.analysis.level(canonical, &config.ark).to_owned(),
            )
        })
        .collect();
    report.ark_max_level = report
        .ark_category_levels
        .values()
        .max()
        .cloned()
        .unwrap_or(report.ark_max_level);
    output.finalize(&target, &report)?;
    match options.format {
        OutputFormat::Human => println!("{}", terminal_summary(&report)),
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string(&report)
                .map_err(|error| ScannerError::Output(error.to_string()))?
        ),
    }
    Ok(exit_code(report.status, options.fail_on))
}
