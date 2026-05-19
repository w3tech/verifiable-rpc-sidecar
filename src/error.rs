use thiserror::Error;

#[derive(Debug, Error)]
pub enum SidecarError {
    #[error("invalid upstream url: {0}")]
    InvalidUpstream(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, SidecarError>;
