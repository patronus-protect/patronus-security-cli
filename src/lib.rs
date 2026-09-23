mod atomic_file;
pub mod auth;
pub mod cli;
pub mod config;
pub mod dashboard;
pub mod distribution;
pub mod error;
pub mod integrations;
pub mod local_settings;
pub mod plugin_policies;
pub mod plugin_settings;
mod protocol_event;
pub mod runtime;
pub mod scanning;

pub(crate) use dashboard::auth as dashboard_auth;
pub use dashboard::server as dashboard_server;
pub use distribution::{maintenance, model_assets, onboarding, releases, support};
pub use scanning::{
    analysis_config, api_client, ark, chunk, content, discovery, inference, output, policy,
    progress, remote_scan, report, target,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const ARK_VERSION: &str = "0.1.8";
