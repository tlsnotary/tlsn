use crate::{
    connection::{ServerCertData, ServerCertOpening, ServerName},
    request::{Request, RequestConfig},
    secrets::Secrets,
    transcript::{Transcript, TranscriptCommitment, TranscriptSecret},
    CryptoProvider,
};

/// Builder for [`Request`].
pub struct RequestBuilder<'a> {
    config: &'a RequestConfig,
    server_name: Option<ServerName>,
    server_cert_data: Option<ServerCertData>,
    transcript: Option<Transcript>,
    transcript_commitments: Vec<TranscriptCommitment>,
    transcript_commitment_secrets: Vec<TranscriptSecret>,
}

impl<'a> RequestBuilder<'a> {
    /// Creates a new request builder.
    pub fn new(config: &'a RequestConfig) -> Self {
        Self {
            config,
            server_name: None,
            server_cert_data: None,
            transcript: None,
            transcript_commitments: Vec::new(),
            transcript_commitment_secrets: Vec::new(),
        }
    }

    /// Sets the server name.
    pub fn server_name(&mut self, name: ServerName) -> &mut Self {
        self.server_name = Some(name);
        self
    }

    /// Sets the server identity data.
    pub fn server_cert_data(&mut self, data: ServerCertData) -> &mut Self {
        self.server_cert_data = Some(data);
        self
    }

    /// Sets the transcript.
    pub fn transcript(&mut self, transcript: Transcript) -> &mut Self {
        self.transcript = Some(transcript);
        self
    }

    /// Sets the transcript commitments.
    pub fn transcript_commitments(
        &mut self,
        secrets: Vec<TranscriptSecret>,
        commitments: Vec<TranscriptCommitment>,
    ) -> &mut Self {
        self.transcript_commitment_secrets = secrets;
        self.transcript_commitments = commitments;
        self
    }

    /// Builds the attestation request and returns the corresponding secrets.
    pub fn build(
        self,
        provider: &CryptoProvider,
    ) -> Result<(Request, Secrets), RequestBuilderError> {
        let Self {
            config,
            server_name,
            server_cert_data,
            transcript,
            transcript_commitments,
            transcript_commitment_secrets,
        } = self;

        let signature_alg = *config.signature_alg();
        let hash_alg = *config.hash_alg();

        let hasher = provider.hash.get(&hash_alg).map_err(|_| {
            RequestBuilderError::new(format!("unsupported hash algorithm: {hash_alg}"))
        })?;

        let server_name =
            server_name.ok_or_else(|| RequestBuilderError::new("server name is missing"))?;

        let server_cert_opening = ServerCertOpening::new(
            server_cert_data
                .ok_or_else(|| RequestBuilderError::new("server identity data is missing"))?,
        );

        let transcript =
            transcript.ok_or_else(|| RequestBuilderError::new("transcript is missing"))?;

        let server_cert_commitment = server_cert_opening.commit(hasher);

        let extensions = config.extensions().to_vec();

        let request = Request {
            signature_alg,
            hash_alg,
            server_cert_commitment,
            extensions,
        };

        let secrets = Secrets {
            server_name,
            server_cert_opening,
            transcript,
            transcript_commitments,
            transcript_commitment_secrets,
        };

        Ok((request, secrets))
    }
}

/// Error for [`RequestBuilder`].
#[derive(Debug, thiserror::Error)]
#[error("request builder error: {message}")]
pub struct RequestBuilderError {
    message: String,
}

impl RequestBuilderError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}
