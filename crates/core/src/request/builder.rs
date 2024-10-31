use rand::{
    distributions::{Distribution, Standard},
    thread_rng,
};

use crate::{
    attestation::{compare_hash_details, FieldId, PLAINTEXT_HASH_INITIAL_FIELD_ID},
    connection::{ServerCertData, ServerCertOpening, ServerName},
    hash::{Blinded, Blinder, HashAlgId, TypedHash},
    request::{Request, RequestConfig},
    secrets::Secrets,
    transcript::{
        encoding::EncodingTree, PlaintextHash, PlaintextHashSecret, Transcript, TranscriptCommitmentKind
    },
    CryptoProvider,
};
use crate::transcript::commit::CommitInfo;

/// Builder for [`Request`].
pub struct RequestBuilder<'a> {
    config: &'a RequestConfig,
    server_name: Option<ServerName>,
    server_cert_data: Option<ServerCertData>,
    encoding_tree: Option<EncodingTree>,
    transcript: Option<Transcript>,
    plaintext_hashes: Option<Vec<CommitInfo>>,
}

impl<'a> RequestBuilder<'a> {
    /// Creates a new request builder.
    pub fn new(config: &'a RequestConfig) -> Self {
        Self {
            config,
            server_name: None,
            server_cert_data: None,
            encoding_tree: None,
            transcript: None,
            plaintext_hashes: None,
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

    /// Sets the tree to commit to the transcript encodings.
    pub fn encoding_tree(&mut self, tree: EncodingTree) -> &mut Self {
        self.encoding_tree = Some(tree);
        self
    }

    /// Sets the transcript.
    pub fn transcript(&mut self, transcript: Transcript) -> &mut Self {
        self.transcript = Some(transcript);
        self
    }

    /// Sets the plaintext hash commitment info.
    pub fn plaintext_hashes(
        &mut self,
        plaintext_hashes: Vec<CommitInfo>,
    ) -> &mut Self {
        self.plaintext_hashes = Some(plaintext_hashes);
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
            encoding_tree,
            transcript,
            plaintext_hashes,
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

        let encoding_commitment_root = encoding_tree.as_ref().map(|tree| tree.root());

        let (pt_hashes, pt_secrets) = match plaintext_hashes {
            Some(mut plaintext_hashes) => {
                if plaintext_hashes.is_empty() {
                    return Err(RequestBuilderError::new("empty plaintext hash details were set"));
                }

                sort_plaintext_hashes(&mut plaintext_hashes);

                let mut field_id = FieldId::new(PLAINTEXT_HASH_INITIAL_FIELD_ID);

                let (pt_hashes, pt_secrets): (Vec<PlaintextHash>, Vec<PlaintextHashSecret>) = plaintext_hashes.into_iter().map(|info|{
                    let alg = if let TranscriptCommitmentKind::Hash{alg} = info.kind() {
                        alg
                    } else {
                        return Err(RequestBuilderError::new("only plaintext commitments are allowed"));
                    };

                    let (dir, idx) = info.idx().clone();

                    let data = transcript.get(dir, &idx).ok_or_else(|| {
                        RequestBuilderError::new(format!(
                            "direction {} and index {:?} were not found in the transcript",
                            dir, &idx
                        ))
                    })?;
                    
                    let  blinder = match info.blinder() {
                        Some(blinder) => {
                            // The hash was computed earlier.
                            blinder.clone()
                        }, 
                        None => {
                            let blinder: Blinder = Standard.sample(&mut thread_rng());
                            blinder
                        }
                    };

                    let hasher = provider
                    .hash
                    .get(alg)
                    .map_err(|_| RequestBuilderError::new("hash provider is missing"))?;

                    #[cfg(feature = "use_poseidon_halo2")]
                    if alg == &HashAlgId::POSEIDON_HALO2 {
                        if idx.count() != 1 {
                            return Err(RequestBuilderError::new("committing to more than one range with POSEIDON_HALO2 is not supported"));
                        } else if idx.len() > crate::hash::POSEIDON_MAX_INPUT_SIZE {
                            return Err(RequestBuilderError::new(format!("committing to more than {} bytes with POSEIDON_HALO2 is not supported", crate::hash::POSEIDON_MAX_INPUT_SIZE)));
                        }
                    }

                    let data = Blinded::new_with_blinder(data.data().to_vec(), blinder.clone());
                    let hash = hasher.hash_blinded(&data);

                    let field = field_id.next(PlaintextHash {
                        direction: dir,
                        idx: idx.clone(),
                        hash: TypedHash {
                            alg: *alg,
                            value: hash
                        },
                    });

                    Ok((field.data, PlaintextHashSecret {
                        blinder,
                        idx,
                        direction: dir,
                        commitment: field.id,
                    }))
                    
                }).collect::<Result<Vec<_>, RequestBuilderError>>()?.into_iter().unzip();

                (Some(pt_hashes), Some(pt_secrets.into()))
            }
            None => (None, None),
        };

        let request = Request {
            signature_alg,
            hash_alg,
            server_cert_commitment,
            encoding_commitment_root,
            plaintext_hashes: pt_hashes,
        };

        let secrets = Secrets {
            server_name,
            server_cert_opening,
            encoding_tree,
            plaintext_hash_secrets: pt_secrets,
            transcript,
        };

        Ok((request, secrets))
    }
}

/// Sorts plaintext hash commitment info in-place.
fn sort_plaintext_hashes(info: &mut [CommitInfo]) {
    info.sort_by(|info1, info2| {
        let TranscriptCommitmentKind::Hash { alg:alg1 } = info1.kind() else {
            panic!();
        };
        let TranscriptCommitmentKind::Hash { alg:alg2 } = info2.kind() else {
            panic!();
        };
        let (dir1, idx1) = info1.idx();
        let (dir2, idx2) = info2.idx();

        compare_hash_details(&(dir1, idx1, alg1), &(dir2, idx2, alg2))
    });
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
