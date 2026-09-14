use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "patronus-security-scanner",
    version,
    disable_help_subcommand = false
)]
#[command(about = "Patronus Security CLI for AI agent protection and security scans")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Guided setup: account, inference, models, check and global plugins.
    Onboarding {
        /// Run the visible injection check without the interactive wizard.
        #[arg(long, conflicts_with_all = ["status", "open"])]
        check: bool,
        /// Open setup in a visible system terminal on macOS.
        #[arg(long, conflicts_with = "status")]
        open: bool,
        #[arg(long)]
        status: bool,
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
    },
    /// Update or uninstall the CLI and its integrations.
    Maintenance {
        #[command(subcommand)]
        command: MaintenanceCommand,
    },
    /// Serve the local dashboard with editable policies and settings.
    Dashboard {
        #[arg(long, default_value_t = 0)]
        port: u16,
    },
    /// Validate, activate and test local dashboard policies.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Sign in to the Control Plane for API and MCP access.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// Serve local request/response scan jobs over a private stdio channel.
    Serve {
        #[arg(long, required = true)]
        stdio: bool,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// Scan a repository, directory or file and save its report.
    Scan {
        #[command(subcommand)]
        target: ScanTarget,
    },
    /// Create or inspect scanner configuration.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Configure runtime hooks and pause protection for individual chats.
    Plugins {
        #[command(subcommand)]
        command: PluginCommand,
    },
    /// Prepare local model files for the configured analysis levels.
    Assets {
        #[command(subcommand)]
        command: AssetsCommand,
    },
    /// Append sanitized hook/MCP metadata and refresh the local HTML dashboard.
    Protocol {
        #[command(subcommand)]
        command: ProtocolCommand,
    },
    /// Manage the Patronus integration for an agent host.
    Integration(IntegrationArgs),
    /// Prepare a redacted support bundle; uploading requires explicit flags.
    SupportUs(SupportArgs),
    /// Print scanner and Ark versions.
    Version,
}

#[derive(Debug, Args)]
pub struct IntegrationArgs {
    #[arg(value_enum)]
    pub host: IntegrationHost,
    #[command(subcommand)]
    pub action: IntegrationAction,
    /// Advanced local marketplace or package override.
    #[arg(long, global = true, hide = true)]
    pub source: Option<PathBuf>,
    #[arg(long, global = true, value_enum, default_value = "user", hide = true)]
    pub scope: IntegrationScope,
    #[arg(long, global = true, hide = true)]
    pub profile: Option<String>,
    /// Preserve host-managed plugin data during uninstall when supported.
    #[arg(long, global = true, hide = true)]
    pub keep_data: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum IntegrationHost {
    Codex,
    Claude,
    Deepseek,
}

#[derive(Debug, Clone, Copy, Subcommand, PartialEq, Eq)]
pub enum IntegrationAction {
    /// Update from the registered marketplace or verified Patronus release.
    Update,
    /// Download, verify and install the plugin for this host.
    Install,
    /// Enable an installed plugin in the selected host.
    Enable,
    /// Disable the plugin while keeping its installation and data.
    Disable,
    /// Remove the plugin registration from the selected host.
    Uninstall,
    /// Report installation and activation state without changing it.
    Status {
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum IntegrationScope {
    User,
    Project,
    Local,
}

impl IntegrationScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Project => "project",
            Self::Local => "local",
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum ScanTarget {
    /// Scan a public HTTPS URL through the API.
    Url(RemoteScanArgs),
    /// Scan a public HTTPS MCP endpoint, optionally selected from a config file.
    Mcp(RemoteScanArgs),
    /// Scan a Git repository, including its supported source and text files.
    Repo {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[command(flatten)]
        options: ScanOptions,
    },
    /// Scan supported files in a directory tree.
    #[command(alias = "dir")]
    Directory {
        path: PathBuf,
        #[command(flatten)]
        options: ScanOptions,
    },
    /// Scan one explicit file and report its coverage and findings.
    File {
        path: PathBuf,
        #[command(flatten)]
        options: ScanOptions,
    },
}

impl ScanTarget {
    pub fn into_parts(self) -> (crate::target::TargetKind, PathBuf, ScanOptions) {
        match self {
            Self::Url(_) | Self::Mcp(_) => unreachable!("remote scans dispatched separately"),
            Self::Repo { path, options } => (crate::target::TargetKind::Repo, path, options),
            Self::Directory { path, options } => {
                (crate::target::TargetKind::Directory, path, options)
            }
            Self::File { path, options } => (crate::target::TargetKind::File, path, options),
        }
    }
}

#[derive(Debug, Args)]
pub struct RemoteScanArgs {
    pub target: String,
    #[arg(long)]
    pub server: Option<String>,
    #[arg(long)]
    pub config: Option<PathBuf>,
    #[arg(long, value_enum, default_value = "human")]
    pub format: OutputFormat,
    #[arg(long, value_enum)]
    pub max_level: Option<MaxLevel>,
    #[arg(long)]
    pub category: Vec<String>,
}

#[derive(Debug, Clone, Args, Default)]
pub struct ScanOptions {
    /// Upload this one file to the rate-limited anonymous API instead of scanning it locally.
    #[arg(long)]
    pub anonymous_api: bool,
    /// Retain analyzed chunk content in output artifacts.
    #[arg(long)]
    pub activate_store_content: bool,
    /// Use only user/explicit configuration, ignoring repository settings.
    #[arg(long)]
    pub no_repo_config: bool,
    #[arg(long)]
    pub config: Option<PathBuf>,
    #[arg(long)]
    pub output: Option<PathBuf>,
    #[arg(long, value_enum, default_value = "human")]
    pub format: OutputFormat,
    #[arg(long, value_enum)]
    pub progress: Option<ProgressMode>,
    #[arg(long, value_enum, default_value = "auto")]
    pub color: ColorMode,
    #[arg(long)]
    pub quiet: bool,
    #[arg(long)]
    pub include: Vec<String>,
    #[arg(long)]
    pub ignore: Vec<String>,
    #[arg(long, value_enum)]
    pub max_level: Option<MaxLevel>,
    #[arg(long)]
    pub category: Vec<String>,
    #[arg(long, value_enum, default_value = "incomplete")]
    pub fail_on: FailOn,
}

#[derive(Debug, Clone, Copy, Default, ValueEnum, PartialEq, Eq)]
pub enum OutputFormat {
    #[default]
    Human,
    Json,
}

#[cfg(test)]
mod anonymous_api_tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn anonymous_file_upload_is_explicit() {
        let cli = Cli::try_parse_from([
            "patronus-security-scanner",
            "scan",
            "file",
            "report.pdf",
            "--anonymous-api",
        ])
        .unwrap();
        let Command::Scan {
            target: ScanTarget::File { options, .. },
        } = cli.command
        else {
            panic!("expected file scan")
        };
        assert!(options.anonymous_api);
        assert!(!options.activate_store_content);

        let cli = Cli::try_parse_from([
            "patronus-security-scanner",
            "scan",
            "file",
            "report.pdf",
            "--activate-store-content",
        ])
        .unwrap();
        let Command::Scan {
            target: ScanTarget::File { options, .. },
        } = cli.command
        else {
            panic!("expected file scan")
        };
        assert!(!options.anonymous_api);
        assert!(options.activate_store_content);
    }
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProgressMode {
    Auto,
    Tty,
    Plain,
    Json,
    Off,
}

#[derive(Debug, Clone, Copy, Default, ValueEnum, PartialEq, Eq)]
pub enum ColorMode {
    #[default]
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MaxLevel {
    L1,
    L2,
    L3,
}

impl MaxLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::L1 => "l1",
            Self::L2 => "l2",
            Self::L3 => "l3",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, ValueEnum, PartialEq, Eq)]
pub enum FailOn {
    Findings,
    #[default]
    Incomplete,
    Never,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Validate and activate a JSON configuration exported by the local dashboard.
    Import { path: PathBuf },
    /// Write the initial user configuration without overwriting an existing file.
    Init {
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long)]
        force: bool,
        #[arg(long, value_enum)]
        provider: Option<crate::config::ProviderMode>,
    },
    /// Print the effective configuration with secret-like fields redacted.
    Print {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, value_enum, default_value = "toml")]
        format: ConfigFormat,
    },
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Print policies for Claude, Codex and DeepSeek text surfaces.
    Show,
    /// List the actual built-in L1 rules and their defaults.
    Rules,
    /// Validate plugin policies JSON without activating it.
    Validate { path: PathBuf },
    /// Validate and activate plugin policies JSON.
    Import { path: PathBuf },
    /// Scan a JSON object with surface and text using the active settings.
    Check { path: PathBuf },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ConfigFormat {
    Toml,
    Json,
}

#[derive(Debug, Subcommand)]
pub enum AssetsCommand {
    /// Check configured models and download only missing assets.
    Prepare {
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
pub enum ProtocolCommand {
    /// Read a sanitized protocol event from stdin and append it to the shared journal.
    Append {
        /// Optional legacy workspace root; defaults to the shared user directory.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Persist the authenticated journal; render HTML separately after the session.
        #[arg(long)]
        journal_only: bool,
    },
    /// Rebuild the shared activity index from completed reports and session journals.
    Render {
        #[arg(long)]
        root: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    /// Open the Control Plane and paste its one-time login code here.
    Login {
        /// Print the link without opening the system browser.
        #[arg(long)]
        no_browser: bool,
    },
    /// Show expiry and account metadata, never the token.
    Status {
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
        /// Verify the token with the Control Plane, including revocation.
        #[arg(long)]
        check: bool,
    },
    /// Read current account usage and limits from the Control Plane.
    Usage {
        #[arg(long, value_enum, default_value = "human")]
        format: OutputFormat,
    },
    /// Print the unexpired bearer token for API or MCP clients.
    Token,
    /// Revoke this token and remove the local credentials.
    Logout {
        /// Forget locally without contacting the Control Plane.
        #[arg(long)]
        local: bool,
    },
}

#[derive(Debug, Args)]
pub struct SupportArgs {
    #[arg(long, conflicts_with = "latest")]
    pub run: Option<PathBuf>,
    #[arg(long, conflicts_with = "run")]
    pub latest: bool,
    #[arg(long)]
    pub include: Vec<PathBuf>,
    #[arg(long)]
    pub exclude: Vec<PathBuf>,
    #[arg(long)]
    pub dry_run: bool,
    #[arg(long)]
    pub bundle_out: Option<PathBuf>,
    #[arg(long)]
    pub yes: bool,
    #[arg(long)]
    pub message: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum PluginCommand {
    /// Print shared plugin settings.
    Show,
    /// Create ~/.patronus-security-scanner/plugins.json with all hooks enabled.
    Init,
    /// Enable or disable a surface for all hosts.
    Hook {
        #[arg(value_parser = ["user_input", "tool_result", "mcp_result"])]
        surface: String,
        #[arg(action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// Pause runtime scans for a native host chat ID.
    Pause {
        #[arg(value_parser = ["codex", "claude", "deepseek"])]
        host: String,
        chat: String,
    },
    /// Resume scans of future input/results; earlier unscanned history remains.
    Resume {
        #[arg(value_parser = ["codex", "claude", "deepseek"])]
        host: String,
        chat: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum MaintenanceCommand {
    /// Update the standalone or Cargo-installed CLI from its public GitHub release source.
    Update,
    /// Remove the CLI; --all also removes the three host integrations first.
    Uninstall {
        #[arg(long)]
        all: bool,
        /// Confirm removal. Reports, settings and credentials are preserved.
        #[arg(long)]
        yes: bool,
    },
}
