use std::error::Error as StdError;
use std::fmt;

/// Fail-closed result of reading a bounded local projection.
///
/// `CorruptProjection` and `TooManyRows` are deliberately payload-free so a
/// caller can report invalid durable state without retaining or formatting any
/// attacker-sized TEXT/BLOB value.
pub enum LocalProjectionReadError {
    InvalidInput,
    CorruptProjection,
    TooManyRows,
    Database(sqlx_core::Error),
}

impl fmt::Debug for LocalProjectionReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput => formatter.write_str("InvalidInput"),
            Self::CorruptProjection => formatter.write_str("CorruptProjection(<redacted>)"),
            Self::TooManyRows => formatter.write_str("TooManyRows"),
            Self::Database(_) => formatter.write_str("Database(<redacted>)"),
        }
    }
}

impl fmt::Display for LocalProjectionReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "invalid bounded local projection read",
            Self::CorruptProjection => "local projection exceeds its durable bounds",
            Self::TooManyRows => "local projection exceeds its row bound",
            Self::Database(_) => "bounded local projection database read failed",
        })
    }
}

impl StdError for LocalProjectionReadError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Database(source) => Some(source),
            _ => None,
        }
    }
}

impl From<sqlx_core::Error> for LocalProjectionReadError {
    fn from(error: sqlx_core::Error) -> Self {
        Self::Database(error)
    }
}
