//! The Keystone error model.

use time::OffsetDateTime;

/// Every fallible Keystone operation returns this error.
///
/// Variants are deliberately coarse: the CLI turns them into user-facing
/// guidance, so a variant exists when the remedy differs, not merely when the
/// cause differs. Notably clock skew is distinguished from certificate
/// problems, because the two look alike in an AWS rejection but need very
/// different fixes.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeystoneError {
    #[error("Secure Enclave is not available")]
    SecureEnclaveUnavailable,

    #[error("Secure Enclave key could not be restored")]
    KeyUnavailable,

    #[error("Secure Enclave operation failed: {0}")]
    SecureEnclave(String),

    #[error("certificate does not match the Secure Enclave public key")]
    CertificateKeyMismatch,

    #[error("certificate expired at {0}")]
    CertificateExpired(OffsetDateTime),

    #[error("certificate is not yet valid")]
    CertificateNotYetValid,

    #[error("certificate chain is invalid: {0}")]
    InvalidCertificateChain(String),

    #[error("required Keystone URI SAN is missing")]
    MissingDeviceSan,

    #[error("certificate is malformed: {0}")]
    InvalidCertificate(String),

    #[error("invalid Keystone configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Keystone profile {0:?} is not configured")]
    UnknownProfile(String),

    #[error("Keystone profile {profile:?} is not ready: {reason}")]
    ProfileIncomplete { profile: String, reason: String },

    #[error("IAM Roles Anywhere rejected the request: {status} {code}")]
    RolesAnywhereRejected {
        status: u16,
        code: String,
        message: String,
    },

    #[error("system clock may be incorrect")]
    ClockSkew,

    #[error("temporary credential response was malformed: {0}")]
    InvalidCredentialResponse(String),

    #[error("network request failed: {0}")]
    Network(String),

    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    #[error("{0}")]
    Other(String),
}

impl KeystoneError {
    /// Attach a human-readable context string to an I/O failure.
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    /// Whether this failure could plausibly succeed if retried as-is.
    ///
    /// Certificate, signature, and configuration failures are permanent: the
    /// same request will be rejected again, so retrying only delays the error
    /// the user needs to see. Throttling and server-side faults are the only
    /// AWS rejections worth another attempt.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Network(_) => true,
            Self::RolesAnywhereRejected { status, .. } => {
                matches!(status, 429 | 500 | 502 | 503 | 504)
            }
            _ => false,
        }
    }
}

pub type Result<T> = std::result::Result<T, KeystoneError>;
