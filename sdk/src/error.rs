//! Error type exported to Kotlin/Swift as a sealed exception hierarchy.

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PerseverusError {
    /// Network or transport failure. Safe to retry.
    #[error("network: {reason}")]
    Network { reason: String },
    /// The server answered with an error.
    #[error("server ({status}): {reason}")]
    Server { status: u16, reason: String },
    /// A server response failed a cryptographic check (DLEQ proof, codebook
    /// id). Treat the server as untrusted; do not retry blindly.
    #[error("verification failed: {reason}")]
    Verification { reason: String },
    #[error("not enough tokens: need {needed}, have {available}")]
    InsufficientTokens { needed: u32, available: u32 },
    #[error("payment not completed yet")]
    NotPaid,
    #[error("invalid argument: {reason}")]
    InvalidArgument { reason: String },
    #[error("not supported: {reason}")]
    Unsupported { reason: String },
    #[error("local storage: {reason}")]
    Storage { reason: String },
    #[error("internal: {reason}")]
    Internal { reason: String },
}

impl PerseverusError {
    pub(crate) fn network(e: impl std::fmt::Display) -> Self {
        Self::Network { reason: e.to_string() }
    }
}

/// Turn a `/v1` error envelope (`{"error":{"code","message",..}}`) into
/// `"code: message"`, so every `Server` error reads the same way. Anything
/// else (already formatted, or a legacy body) is returned unchanged.
pub(crate) fn server_reason(body: String) -> String {
    serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| {
            let e = v.get("error")?;
            match (e.get("code").and_then(|c| c.as_str()), e.get("message").and_then(|m| m.as_str())) {
                (Some(c), Some(m)) => Some(format!("{c}: {m}")),
                _ => e.as_str().map(String::from),
            }
        })
        .unwrap_or(body)
}

impl From<reqwest::Error> for PerseverusError {
    fn from(e: reqwest::Error) -> Self {
        match e.status() {
            Some(s) => Self::Server { status: s.as_u16(), reason: e.to_string() },
            None => Self::network(e),
        }
    }
}

impl From<perseverus_client_native::QueryClientError> for PerseverusError {
    fn from(e: perseverus_client_native::QueryClientError) -> Self {
        use perseverus_client_native::QueryClientError as Q;
        match e {
            Q::Http(h) => h.into(),
            Q::ServerStatus { status, body } => Self::Server { status, reason: server_reason(body) },
            other => Self::Internal { reason: other.to_string() },
        }
    }
}

impl From<perseverus_client_native::IssuanceClientError> for PerseverusError {
    fn from(e: perseverus_client_native::IssuanceClientError) -> Self {
        use perseverus_client_native::IssuanceClientError as I;
        match e {
            I::Http(h) => h.into(),
            I::ServerStatus { status, body } => Self::Server { status, reason: server_reason(body) },
            I::Crypto(c) => Self::Verification { reason: c.to_string() },
            I::Transport(t) => Self::network(t),
            other => Self::Internal { reason: other.to_string() },
        }
    }
}

impl From<perseverus_client_native::SpendClientError> for PerseverusError {
    fn from(e: perseverus_client_native::SpendClientError) -> Self {
        use perseverus_client_native::SpendClientError as S;
        match e {
            S::Http(h) => h.into(),
            S::ServerStatus { status, body } => Self::Server { status, reason: server_reason(body) },
            S::Crypto(c) => Self::Verification { reason: c.to_string() },
            other => Self::Internal { reason: other.to_string() },
        }
    }
}
