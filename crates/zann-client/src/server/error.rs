use crate::config::ConfigError;
use crate::remote::auth::AuthHttpError;

#[derive(Debug, thiserror::Error)]
#[error("{source}")]
pub struct ServerError {
    #[source]
    source: Source,
}

#[derive(Debug, thiserror::Error)]
enum Source {
    #[error(transparent)]
    Transport(#[from] AuthHttpError),
    #[error(transparent)]
    Configuration(#[from] ConfigError),
    #[error(transparent)]
    Credential(#[from] crate::config::CredentialPortError),
    #[error(transparent)]
    Secrets(#[from] crate::secrets::SecretsClientError),
    #[error("invalid item identifier")]
    Uuid(#[source] uuid::Error),
    #[error("invalid item timestamp")]
    Timestamp(#[source] chrono::ParseError),
    #[error(transparent)]
    Secret(#[from] crate::config::CredentialSecretError),
    #[error("invalid server input: {0}")]
    Input(&'static str),
    #[error("server identity requires explicit trust")]
    Trust,
    #[error("server identity proof rejected: {0}")]
    IdentityProof(String),
}

impl From<AuthHttpError> for ServerError {
    fn from(source: AuthHttpError) -> Self {
        Self {
            source: Source::Transport(source),
        }
    }
}
impl From<ConfigError> for ServerError {
    fn from(source: ConfigError) -> Self {
        Self {
            source: Source::Configuration(source),
        }
    }
}
impl ServerError {
    pub(super) fn input(reason: &'static str) -> Self {
        Self {
            source: Source::Input(reason),
        }
    }
    pub(super) fn trust() -> Self {
        Self {
            source: Source::Trust,
        }
    }
    pub(super) fn identity_proof(reason: String) -> Self {
        Self {
            source: Source::IdentityProof(reason),
        }
    }
}

impl From<crate::config::CredentialPortError> for ServerError {
    fn from(source: crate::config::CredentialPortError) -> Self {
        Self {
            source: Source::Credential(source),
        }
    }
}

impl From<crate::secrets::SecretsClientError> for ServerError {
    fn from(source: crate::secrets::SecretsClientError) -> Self {
        Self {
            source: Source::Secrets(source),
        }
    }
}

impl From<uuid::Error> for ServerError {
    fn from(source: uuid::Error) -> Self {
        Self {
            source: Source::Uuid(source),
        }
    }
}
impl From<chrono::ParseError> for ServerError {
    fn from(source: chrono::ParseError) -> Self {
        Self {
            source: Source::Timestamp(source),
        }
    }
}
impl From<crate::config::CredentialSecretError> for ServerError {
    fn from(source: crate::config::CredentialSecretError) -> Self {
        Self {
            source: Source::Secret(source),
        }
    }
}
