use std::fmt::Display;

/// TLSNotary error.
///
/// Errors are categorized by kind:
///
/// - **User** ([`is_user`](Self::is_user)): e.g. rejected by the remote party.
/// - **IO** ([`is_io`](Self::is_io)): network or communication failure.
/// - **Internal** ([`is_internal`](Self::is_internal)): an unknown internal
///   error in the library.
/// - **Config** ([`is_config`](Self::is_config)): invalid configuration
///   provided by the user.
///
/// The [`msg`](Self::msg) method returns additional context if available, such
/// as a rejection message provided by a verifier.
#[derive(Debug, thiserror::Error)]
pub struct Error {
    kind: ErrorKind,
    msg: Option<String>,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl Error {
    pub(crate) fn io() -> Self {
        Self {
            kind: ErrorKind::Io,
            msg: None,
            source: None,
        }
    }

    pub(crate) fn internal() -> Self {
        Self {
            kind: ErrorKind::Internal,
            msg: None,
            source: None,
        }
    }

    pub(crate) fn user() -> Self {
        Self {
            kind: ErrorKind::User,
            msg: None,
            source: None,
        }
    }

    pub(crate) fn config() -> Self {
        Self {
            kind: ErrorKind::Config,
            msg: None,
            source: None,
        }
    }

    pub(crate) fn with_msg(mut self, msg: impl Into<String>) -> Self {
        self.msg = Some(msg.into());
        self
    }

    pub(crate) fn with_source<T>(mut self, source: T) -> Self
    where
        T: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        self.source = Some(source.into());
        self
    }

    /// Returns `true` if the error was user created.
    pub fn is_user(&self) -> bool {
        self.kind.is_user()
    }

    /// Returns `true` if the error originated from an IO error.
    pub fn is_io(&self) -> bool {
        self.kind.is_io()
    }

    /// Returns `true` if the error originated from an internal bug.
    pub fn is_internal(&self) -> bool {
        self.kind.is_internal()
    }

    /// Returns `true` if the error originated from invalid configuration.
    pub fn is_config(&self) -> bool {
        self.kind.is_config()
    }

    /// Returns the error message if available.
    pub fn msg(&self) -> Option<&str> {
        self.msg.as_deref()
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            ErrorKind::User => write!(f, "user error")?,
            ErrorKind::Io => write!(f, "io error")?,
            ErrorKind::Internal => write!(f, "internal error")?,
            ErrorKind::Config => write!(f, "config error")?,
        }

        if let Some(msg) = &self.msg {
            write!(f, ": {msg}")?;
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {source}")?;
        }

        Ok(())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::io().with_source(e)
    }
}

impl From<mpz_common::ContextError> for Error {
    fn from(e: mpz_common::ContextError) -> Self {
        Self::internal().with_msg("context error").with_source(e)
    }
}

impl From<mpc_tls::MpcTlsError> for Error {
    fn from(e: mpc_tls::MpcTlsError) -> Self {
        Self::internal().with_msg("mpc-tls error").with_source(e)
    }
}

impl From<tlsn_mux::ConnectionError> for Error {
    fn from(e: tlsn_mux::ConnectionError) -> Self {
        Self::io().with_msg("mux connection error").with_source(e)
    }
}

#[derive(Debug)]
enum ErrorKind {
    User,
    Io,
    Internal,
    Config,
}

impl ErrorKind {
    fn is_user(&self) -> bool {
        matches!(self, ErrorKind::User)
    }

    fn is_io(&self) -> bool {
        matches!(self, ErrorKind::Io)
    }

    fn is_internal(&self) -> bool {
        matches!(self, ErrorKind::Internal)
    }

    fn is_config(&self) -> bool {
        matches!(self, ErrorKind::Config)
    }
}
