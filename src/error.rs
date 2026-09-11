use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum ScannerError {
    #[error("invalid configuration from {source_name}: {message}")]
    Config {
        source_name: String,
        message: String,
    },
    #[error("invalid target {path}: {message}")]
    Target { path: PathBuf, message: String },
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("Ark error: {0}")]
    Ark(String),
    #[error("{message}")]
    Api {
        kind: patronus_api_client::ErrorKind,
        message: String,
        code: Option<String>,
        retry_after: Option<u64>,
        details: Option<Box<serde_json::Value>>,
    },
    #[error("output error: {0}")]
    Output(String),
    #[error("support bundle error: {0}")]
    Support(String),
    #[error("integration error: {0}")]
    Integration(String),
}

pub type Result<T> = std::result::Result<T, ScannerError>;

pub trait IoContext<T> {
    fn at(self, path: impl Into<PathBuf>) -> Result<T>;
}

impl<T> IoContext<T> for std::io::Result<T> {
    fn at(self, path: impl Into<PathBuf>) -> Result<T> {
        let path = path.into();
        self.map_err(|source| ScannerError::Io { path, source })
    }
}
