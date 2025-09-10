//! Proving flow for prover and verifier. Handles necessary parts for commitment
//! creation and selective disclosure.
//!
//! - transcript reference storage in [`transcript`]
//! - transcript's plaintext authentication in [`auth`]
//! - decoding of transcript in [`decode`]
//! - encoding commitments in [`encoding`]
//! - hash commitments in [`hash`]

use crate::{
    EncodingMemory, EncodingVm,
    commit::{
        auth::{AuthError, Authenticator},
        decode::{DecodeError, check_transcript_length, decode_transcript, verify_transcript},
        encoding::EncodingCreator,
        hash::{HashCommitError, PlaintextHasher},
    },
    zk_aes_ctr::ZkAesCtr,
};
use encoding::{EncodingError, Encodings};
use mpc_tls::SessionKeys;
use mpz_common::Context;
use mpz_garble_core::Delta;
use mpz_memory_core::binary::Binary;
use mpz_vm_core::VmError;
use rand::Rng;
use serio::{SinkExt, stream::IoStreamExt};
use tlsn_core::{
    ProveConfig, ProvePayload, ProverOutput, VerifierOutput,
    connection::{HandshakeData, HandshakeVerificationError, ServerName},
    hash::{HashAlgId, TypedHash},
    transcript::{
        Direction, Idx, PartialTranscript, TlsTranscript, TranscriptCommitment, TranscriptSecret,
        encoding::{EncoderSecret, EncodingCommitment, EncodingTree},
    },
    webpki::{RootCertStore, ServerCertVerifier, ServerCertVerifierError},
};

mod auth;
mod decode;
mod encoding;
mod hash;
mod transcript;

pub(crate) use encoding::ENCODING_SIZE;
pub(crate) use transcript::TranscriptRefs;

/// Internal proving state used by [`Prover`](crate::prover::Prover) and
/// [`Verifier`](crate::verifier::Verifier).
///
/// Manages the prover and verifier flow. Bundles plaintext authentication,
/// creation of commitments, selective disclosure and verification of
/// servername.
pub(crate) struct ProvingState<'a> {
    partial: Option<PartialTranscript>,

    server_identity: Option<(ServerName, HandshakeData)>,
    verified_server_name: Option<ServerName>,

    authenticator: Authenticator,
    encoding: EncodingCreator,
    encodings_transferred: bool,
    hasher: PlaintextHasher,

    transcript: &'a TlsTranscript,
    transcript_refs: &'a mut TranscriptRefs,
}

impl<'a> ProvingState<'a> {
    /// Creates a new proving state for the prover.
    ///
    /// # Arguments
    ///
    /// * `config` - The config for proving.
    /// * `transcript` - The TLS transcript.
    /// * `transcript_refs` - The transcript references.
    /// * `encodings_transferred` - If the encoding protocol has already been
    ///   executed.
    pub(crate) fn for_prover(
        config: ProveConfig,
        transcript: &'a TlsTranscript,
        transcript_refs: &'a mut TranscriptRefs,
        encodings_transferred: bool,
    ) -> Self {
        let mut encoding_hash_id = None;
        let mut encoding_idxs: Vec<(Direction, Idx)> = Vec::new();
        let mut hash_idxs: Vec<(Direction, Idx, HashAlgId)> = Vec::new();

        if let Some(commit_config) = config.transcript_commit() {
            encoding_hash_id = Some(*commit_config.encoding_hash_alg());

            encoding_idxs = commit_config
                .iter_encoding()
                .map(|(dir, idx)| (*dir, idx.clone()))
                .collect();
            hash_idxs = commit_config
                .iter_hash()
                .map(|((dir, idx), alg)| (*dir, idx.clone(), *alg))
                .collect();
        }

        let partial = config.into_transcript();
        let authenticator =
            Authenticator::new(encoding_idxs.iter(), hash_idxs.iter(), partial.as_ref());

        let encoding = EncodingCreator::new(encoding_hash_id, encoding_idxs);
        let hasher = PlaintextHasher::new(hash_idxs.iter());

        Self {
            partial,
            server_identity: None,
            verified_server_name: None,
            authenticator,
            encoding,
            encodings_transferred,
            hasher,
            transcript,
            transcript_refs,
        }
    }

    /// Creates a new proving state for the verifier.
    ///
    /// # Arguments
    ///
    /// * `payload` - The prove payload.
    /// * `transcript` - The TLS transcript.
    /// * `transcript_refs` - The transcript references.
    /// * `verified_server_name` - The verified server name.
    /// * `encodings_transferred` - If the encoding protocol has already been
    ///   executed.
    pub(crate) fn for_verifier(
        payload: ProvePayload,
        transcript: &'a TlsTranscript,
        transcript_refs: &'a mut TranscriptRefs,
        verified_server_name: Option<ServerName>,
        encodings_transferred: bool,
    ) -> Self {
        let mut encoding_idxs: Vec<(Direction, Idx)> = Vec::new();
        let mut hash_idxs: Vec<(Direction, Idx, HashAlgId)> = Vec::new();

        if let Some(commit_config) = payload.transcript_commit.as_ref() {
            encoding_idxs = commit_config.iter_encoding().cloned().collect();
            hash_idxs = commit_config.iter_hash().cloned().collect();
        }

        let authenticator = Authenticator::new(
            encoding_idxs.iter(),
            hash_idxs.iter(),
            payload.transcript.as_ref(),
        );

        let encoding = EncodingCreator::new(None, encoding_idxs);
        let hasher = PlaintextHasher::new(hash_idxs.iter());

        Self {
            partial: payload.transcript,
            server_identity: payload.handshake,
            verified_server_name,
            authenticator,
            encoding,
            encodings_transferred,
            hasher,
            transcript,
            transcript_refs,
        }
    }

    /// Proves the transcript and generates the prover output.
    ///
    /// Returns the output for the prover and if the encoding protocol has been
    /// executed.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine.
    /// * `ctx` - The thread context.
    /// * `zk_aes_sent` - ZkAes for the sent traffic.
    /// * `zk_aes_recv` - ZkAes for the received traffic.
    /// * `keys` - The TLS session keys.
    pub(crate) async fn prove(
        mut self,
        vm: &mut (impl EncodingVm<Binary> + Send),
        ctx: &mut Context,
        zk_aes_sent: &mut ZkAesCtr,
        zk_aes_recv: &mut ZkAesCtr,
        keys: SessionKeys,
    ) -> Result<(ProverOutput, bool), CommitError> {
        // Authenticates only necessary parts of the transcript. Proof is not needed on
        // the prover side.
        let _ =
            self.authenticator
                .auth_sent(vm, zk_aes_sent, self.transcript, self.transcript_refs)?;
        let _ =
            self.authenticator
                .auth_recv(vm, zk_aes_recv, self.transcript, self.transcript_refs)?;

        vm.execute_all(ctx).await?;

        // Decodes the transcript parts that should be disclosed.
        if self.has_decoding_ranges() {
            decode_transcript(
                vm,
                keys.server_write_key,
                keys.server_write_iv,
                self.authenticator.decoding(),
                self.transcript_refs,
            )?;
        }

        let mut output = ProverOutput::default();

        // Creates encoding commitments if necessary.
        if self.has_encoding_ranges() {
            let (commitment, secret) = self.receive_encodings(vm, ctx).await?;

            output
                .transcript_commitments
                .push(TranscriptCommitment::Encoding(commitment));
            output
                .transcript_secrets
                .push(TranscriptSecret::Encoding(secret));
        }

        // Creates hash commitments if necessary.
        let hash_output = if self.has_hash_ranges() {
            Some(self.hasher.prove(vm, self.transcript_refs)?)
        } else {
            None
        };

        vm.execute_all(ctx).await?;

        if let Some((commitments, secrets)) = hash_output {
            let commitments = commitments.try_recv()?;

            for (hash, secret) in commitments.into_iter().zip(secrets) {
                output
                    .transcript_commitments
                    .push(TranscriptCommitment::Hash(hash));
                output
                    .transcript_secrets
                    .push(TranscriptSecret::Hash(secret));
            }
        }

        Ok((output, self.encodings_transferred))
    }

    /// Verifies the transcript and generates the verifier output.
    ///
    /// Returns the output for the verifier and if the encoding protocol has
    /// been executed.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine.
    /// * `ctx` - The thread context.
    /// * `zk_aes_sent` - ZkAes for the sent traffic.
    /// * `zk_aes_recv` - ZkAes for the received traffic.
    /// * `keys` - The TLS session keys.
    /// * `delta` - The delta.
    /// * `certs` - The certificate chain.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn verify(
        mut self,
        vm: &mut (impl EncodingVm<Binary> + Send),
        ctx: &mut Context,
        zk_aes_sent: &mut ZkAesCtr,
        zk_aes_recv: &mut ZkAesCtr,
        keys: SessionKeys,
        delta: Delta,
        certs: Option<&RootCertStore>,
    ) -> Result<(VerifierOutput, bool), CommitError> {
        self.verify_server_identity(certs)?;

        // Authenticate only necessary parts of the transcript.
        let sent_proof =
            self.authenticator
                .auth_sent(vm, zk_aes_sent, self.transcript, self.transcript_refs)?;
        let recv_proof =
            self.authenticator
                .auth_recv(vm, zk_aes_recv, self.transcript, self.transcript_refs)?;

        vm.execute_all(ctx).await?;

        // Verify the plaintext proofs.
        sent_proof.verify()?;
        recv_proof.verify()?;

        // Decodes the transcript parts that should be disclosed and checks the
        // transcript length.
        if self.has_decoding_ranges() {
            check_transcript_length(self.partial.as_ref(), self.transcript)?;
            decode_transcript(
                vm,
                keys.server_write_key,
                keys.server_write_iv,
                self.authenticator.decoding(),
                self.transcript_refs,
            )?;
        }

        let mut output = VerifierOutput::default();

        // Creates encoding commitments if necessary.
        if self.has_encoding_ranges() {
            let commitment = self.transfer_encodings(vm, ctx, delta).await?;

            output
                .transcript_commitments
                .push(TranscriptCommitment::Encoding(commitment));
        }

        // Create hash commitments if necessary.
        let hash_output = if self.has_hash_ranges() {
            Some(self.hasher.verify(vm, self.transcript_refs)?)
        } else {
            None
        };

        vm.execute_all(ctx).await?;

        if let Some(commitments) = hash_output {
            let commitments = commitments.try_recv()?;

            for hash in commitments.into_iter() {
                output
                    .transcript_commitments
                    .push(TranscriptCommitment::Hash(hash));
            }
        }

        // Verify revealed data.
        if self.has_decoding_ranges() {
            verify_transcript(
                vm,
                keys.server_write_key,
                keys.server_write_iv,
                self.authenticator.decoding(),
                self.partial.as_ref(),
                self.transcript_refs,
                self.transcript,
            )?;
        }

        output.transcript = self.partial;
        output.server_name = self.verified_server_name;

        Ok((output, self.encodings_transferred))
    }

    /// Checks the server identity.
    ///
    /// # Arguments
    ///
    /// * `root_store` - Contains root certificates.
    fn verify_server_identity(
        &mut self,
        root_store: Option<&RootCertStore>,
    ) -> Result<(), CommitError> {
        if !self.has_server_identity() || self.verified_server_name.is_some() {
            return Ok(());
        }

        let Some((server_name, handshake_data)) = self.server_identity.as_ref() else {
            return Err(CommitError(ErrorRepr::MissingCertChain));
        };

        let verifier = if let Some(root_store) = root_store {
            ServerCertVerifier::new(root_store)?
        } else {
            ServerCertVerifier::mozilla()
        };

        let time = self.transcript.time();
        let ephemeral_key = self.transcript.server_ephemeral_key();

        handshake_data.verify(&verifier, time, ephemeral_key, server_name)?;
        self.verified_server_name = Some(server_name.clone());

        Ok(())
    }

    /// Compute the encoding adjustments to send to the prover.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine.
    /// * `ctx` - The thread context.
    /// * `delta` - The Delta.
    async fn transfer_encodings(
        &mut self,
        vm: &mut dyn EncodingMemory<Binary>,
        ctx: &mut Context,
        delta: Delta,
    ) -> Result<EncodingCommitment, CommitError> {
        if self.encodings_transferred {
            return Err(CommitError(ErrorRepr::EncodingOnlyOnce));
        }
        self.encodings_transferred = true;

        let secret = EncoderSecret::new(rand::rng().random(), delta.as_block().to_bytes());

        let encodings = self.encoding.transfer(vm, secret, self.transcript_refs)?;
        let frame_limit = self.encoding_size().saturating_add(ctx.io().limit());

        ctx.io_mut().with_limit(frame_limit).send(encodings).await?;
        let root: TypedHash = ctx.io_mut().expect_next().await?;
        ctx.io_mut().send(secret).await?;

        let commitment = EncodingCommitment { root, secret };
        Ok(commitment)
    }

    /// Receive the encoding adjustments from the verifier and adjust the prover
    /// encodings.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine.
    /// * `ctx` - The thread context.
    async fn receive_encodings(
        &mut self,
        vm: &mut dyn EncodingMemory<Binary>,
        ctx: &mut Context,
    ) -> Result<(EncodingCommitment, EncodingTree), CommitError> {
        if self.encodings_transferred {
            return Err(CommitError(ErrorRepr::EncodingOnlyOnce));
        }
        self.encodings_transferred = true;

        let frame_limit = self.encoding_size().saturating_add(ctx.io().limit());

        let encodings: Encodings = ctx.io_mut().with_limit(frame_limit).expect_next().await?;
        let (root, tree) = self.encoding.receive(vm, encodings, self.transcript_refs)?;

        ctx.io_mut().send(root).await?;
        let secret: EncoderSecret = ctx.io_mut().expect_next().await?;

        let commitment = EncodingCommitment { root, secret };
        Ok((commitment, tree))
    }

    /// Returns the size of the encodings in bytes.
    fn encoding_size(&self) -> usize {
        let (sent, recv) = self.authenticator.encoding();
        ENCODING_SIZE * (sent.len() + recv.len())
    }

    /// Returns if there are encoding ranges present.
    fn has_encoding_ranges(&self) -> bool {
        let (sent, recv) = self.authenticator.encoding();
        !sent.is_empty() || !recv.is_empty()
    }

    /// Returns if there are hash ranges present.
    fn has_hash_ranges(&self) -> bool {
        let (sent, recv) = self.authenticator.hash();
        !sent.is_empty() || !recv.is_empty()
    }

    /// Returns if there are decoding ranges present.
    fn has_decoding_ranges(&self) -> bool {
        let (sent, recv) = self.authenticator.decoding();
        !sent.is_empty() || !recv.is_empty()
    }

    /// Returns if there is a server identity present.
    fn has_server_identity(&self) -> bool {
        self.server_identity.is_some()
    }
}

/// Error for commitments.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct CommitError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
#[error("commit error: {0}")]
enum ErrorRepr {
    #[error("VM error: {0}")]
    Vm(VmError),
    #[error("IO error: {0}")]
    Io(std::io::Error),
    #[error("hash commit error: {0}")]
    Hash(HashCommitError),
    #[error("encoding error: {0}")]
    Encoding(EncodingError),
    #[error("encoding commitments can be created only once")]
    EncodingOnlyOnce,
    #[error("decode error: {0}")]
    Decode(DecodeError),
    #[error("authentication error: {0}")]
    Auth(AuthError),
    #[error("cert chain missing for verifying server identity")]
    MissingCertChain,
    #[error("failed to verify server name")]
    VerifyServerName(HandshakeVerificationError),
    #[error("cert verifier error: {0}")]
    CertVerifier(ServerCertVerifierError),
}

impl From<VmError> for CommitError {
    fn from(err: VmError) -> Self {
        Self(ErrorRepr::Vm(err))
    }
}
impl From<std::io::Error> for CommitError {
    fn from(err: std::io::Error) -> Self {
        Self(ErrorRepr::Io(err))
    }
}

impl From<AuthError> for CommitError {
    fn from(value: AuthError) -> Self {
        CommitError(ErrorRepr::Auth(value))
    }
}

impl From<EncodingError> for CommitError {
    fn from(value: EncodingError) -> Self {
        CommitError(ErrorRepr::Encoding(value))
    }
}

impl From<DecodeError> for CommitError {
    fn from(value: DecodeError) -> Self {
        CommitError(ErrorRepr::Decode(value))
    }
}

impl From<HashCommitError> for CommitError {
    fn from(value: HashCommitError) -> Self {
        CommitError(ErrorRepr::Hash(value))
    }
}

impl From<ServerCertVerifierError> for CommitError {
    fn from(value: ServerCertVerifierError) -> Self {
        CommitError(ErrorRepr::CertVerifier(value))
    }
}

impl From<HandshakeVerificationError> for CommitError {
    fn from(value: HandshakeVerificationError) -> Self {
        CommitError(ErrorRepr::VerifyServerName(value))
    }
}

#[cfg(test)]
mod tests {
    use mpc_tls::SessionKeys;
    use mpz_common::context::test_st_context;
    use mpz_garble_core::Delta;
    use mpz_memory_core::{
        Array, MemoryExt, ViewExt,
        binary::{Binary, U8},
    };
    use mpz_ot::ideal::rcot::ideal_rcot;
    use mpz_vm_core::Execute;
    use mpz_zk::{Prover, ProverConfig, Verifier, VerifierConfig};
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use rangeset::{RangeSet, UnionMut};
    use rstest::{fixture, rstest};
    use tlsn_core::{
        ProveConfig, ProvePayload,
        connection::{HandshakeData, ServerName},
        fixtures::transcript::{IV, KEY, RECV_LEN, SENT_LEN, transcript_fixture},
        hash::HashAlgId,
        transcript::{
            Direction, TlsTranscript, TranscriptCommitConfig, TranscriptCommitment,
            TranscriptCommitmentKind, TranscriptSecret,
        },
    };

    use crate::{
        EncodingVm, Role,
        commit::{ProvingState, transcript::TranscriptRefs},
        zk_aes_ctr::ZkAesCtr,
    };

    #[tokio::main]
    #[rstest]
    async fn test_commit(
        transcript: TlsTranscript,
        transcript_refs: TranscriptRefs,
        prove_config: ProveConfig,
        prove_payload: ProvePayload,
    ) {
        let (mut ctx_p, mut ctx_v) = test_st_context(8);

        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (ot_send, ot_recv) = ideal_rcot(rng.random(), delta.into_inner());

        let mut prover = Prover::new(ProverConfig::default(), ot_recv);
        let mut verifier = Verifier::new(VerifierConfig::default(), delta, ot_send);

        let mut refs_prover = transcript_refs.clone();
        let mut refs_verifier = transcript_refs;

        let keys_prover = set_keys(&mut prover, KEY, IV, Role::Prover);

        // not needed
        let mac_key_prover = prover.alloc().unwrap();
        prover.mark_public(mac_key_prover).unwrap();
        prover.assign(mac_key_prover, [0_u8; 16]).unwrap();
        prover.commit(mac_key_prover).unwrap();

        let session_keys_prover = SessionKeys {
            client_write_key: keys_prover.0,
            client_write_iv: keys_prover.1,
            server_write_key: keys_prover.0,
            server_write_iv: keys_prover.1,
            server_write_mac_key: mac_key_prover,
        };

        let keys_verifier = set_keys(&mut verifier, KEY, IV, Role::Verifier);

        // not needed
        let mac_key_verifier = verifier.alloc().unwrap();
        verifier.mark_public(mac_key_verifier).unwrap();
        verifier.assign(mac_key_verifier, [0_u8; 16]).unwrap();
        verifier.commit(mac_key_verifier).unwrap();

        let session_keys_verifier = SessionKeys {
            client_write_key: keys_verifier.0,
            client_write_iv: keys_verifier.1,
            server_write_key: keys_verifier.0,
            server_write_iv: keys_verifier.1,
            server_write_mac_key: mac_key_verifier,
        };

        let prover_state =
            ProvingState::for_prover(prove_config, &transcript, &mut refs_prover, false);

        let mut zk_prover_sent = ZkAesCtr::new(Role::Prover);
        zk_prover_sent.set_key(keys_prover.0, keys_prover.1);
        zk_prover_sent.alloc(&mut prover, SENT_LEN).unwrap();

        let mut zk_prover_recv = ZkAesCtr::new(Role::Prover);
        zk_prover_recv.set_key(keys_prover.0, keys_prover.1);
        zk_prover_recv.alloc(&mut prover, RECV_LEN).unwrap();

        let verifier_state =
            ProvingState::for_verifier(prove_payload, &transcript, &mut refs_verifier, None, false);

        let mut zk_verifier_sent = ZkAesCtr::new(Role::Verifier);
        zk_verifier_sent.set_key(keys_verifier.0, keys_verifier.1);
        zk_verifier_sent.alloc(&mut verifier, SENT_LEN).unwrap();

        let mut zk_verifier_recv = ZkAesCtr::new(Role::Verifier);
        zk_verifier_recv.set_key(keys_verifier.0, keys_verifier.1);
        zk_verifier_recv.alloc(&mut verifier, RECV_LEN).unwrap();

        tokio::try_join!(
            prover.execute_all(&mut ctx_p),
            verifier.execute_all(&mut ctx_v)
        )
        .unwrap();

        let ((prover_output, _), (verifier_output, _)) = tokio::try_join!(
            prover_state.prove(
                &mut prover,
                &mut ctx_p,
                &mut zk_prover_sent,
                &mut zk_prover_recv,
                session_keys_prover
            ),
            verifier_state.verify(
                &mut verifier,
                &mut ctx_v,
                &mut zk_verifier_sent,
                &mut zk_verifier_recv,
                session_keys_verifier,
                delta,
                None
            )
        )
        .unwrap();

        let prover_commitments = prover_output.transcript_commitments;
        let prover_secrets = prover_output.transcript_secrets;

        let verifier_commitments = verifier_output.transcript_commitments;
        let verifier_server = verifier_output.server_name;
        let partial = verifier_output.transcript;

        prover_commitments
            .iter()
            .any(|commitment| matches!(commitment, TranscriptCommitment::Encoding(_)));

        prover_commitments
            .iter()
            .any(|commitment| matches!(commitment, TranscriptCommitment::Hash(_)));

        prover_secrets
            .iter()
            .any(|secret| matches!(secret, TranscriptSecret::Encoding(_)));

        prover_secrets
            .iter()
            .any(|secret| matches!(secret, TranscriptSecret::Hash(_)));

        verifier_commitments
            .iter()
            .any(|commitment| matches!(commitment, TranscriptCommitment::Encoding(_)));

        verifier_commitments
            .iter()
            .any(|commitment| matches!(commitment, TranscriptCommitment::Hash(_)));

        assert!(verifier_server.is_some());
        assert!(partial.is_some());
    }

    #[fixture]
    fn prove_config(
        decoding: (RangeSet<usize>, RangeSet<usize>),
        encoding: (RangeSet<usize>, RangeSet<usize>),
        hash: (RangeSet<usize>, RangeSet<usize>),
        transcript: TlsTranscript,
    ) -> ProveConfig {
        let transcript = transcript.to_transcript().unwrap();
        let mut builder = ProveConfig::builder(&transcript);

        builder.reveal_sent(&decoding.0).unwrap();
        builder.reveal_recv(&decoding.1).unwrap();
        builder.server_identity();

        let mut transcript_commit = TranscriptCommitConfig::builder(&transcript);
        transcript_commit.encoding_hash_alg(HashAlgId::SHA256);

        transcript_commit
            .commit_with_kind(
                &encoding.0,
                Direction::Sent,
                TranscriptCommitmentKind::Encoding,
            )
            .unwrap();
        transcript_commit
            .commit_with_kind(
                &encoding.1,
                Direction::Received,
                TranscriptCommitmentKind::Encoding,
            )
            .unwrap();

        transcript_commit
            .commit_with_kind(
                &hash.0,
                Direction::Sent,
                TranscriptCommitmentKind::Hash {
                    alg: HashAlgId::SHA256,
                },
            )
            .unwrap();
        transcript_commit
            .commit_with_kind(
                &hash.1,
                Direction::Received,
                TranscriptCommitmentKind::Hash {
                    alg: HashAlgId::SHA256,
                },
            )
            .unwrap();

        let transcript_commit = transcript_commit.build().unwrap();
        builder.transcript_commit(transcript_commit);

        builder.build().unwrap()
    }

    #[fixture]
    fn prove_payload(prove_config: ProveConfig, transcript: TlsTranscript) -> ProvePayload {
        let handshake = HandshakeData::new(&transcript);
        let server_name = ServerName::Dns("tlsnotary.org".try_into().unwrap());

        ProvePayload::new(&prove_config, Some((server_name, handshake)))
    }

    fn set_keys(
        vm: &mut dyn EncodingVm<Binary>,
        key_value: [u8; 16],
        iv_value: [u8; 4],
        role: Role,
    ) -> (Array<U8, 16>, Array<U8, 4>) {
        let key: Array<U8, 16> = vm.alloc().unwrap();
        let iv: Array<U8, 4> = vm.alloc().unwrap();

        if let Role::Prover = role {
            vm.mark_private(key).unwrap();
            vm.mark_private(iv).unwrap();

            vm.assign(key, key_value).unwrap();
            vm.assign(iv, iv_value).unwrap();
        } else {
            vm.mark_blind(key).unwrap();
            vm.mark_blind(iv).unwrap();
        }

        vm.commit(key).unwrap();
        vm.commit(iv).unwrap();

        (key, iv)
    }

    #[fixture]
    fn decoding() -> (RangeSet<usize>, RangeSet<usize>) {
        let mut sent = RangeSet::default();
        let mut recv = RangeSet::default();

        sent.union_mut(&(600..1100));
        sent.union_mut(&(3450..3451));

        recv.union_mut(&(200..405));
        recv.union_mut(&(3182..4190));

        (sent, recv)
    }

    #[fixture]
    fn encoding() -> (RangeSet<usize>, RangeSet<usize>) {
        let mut sent = RangeSet::default();
        let mut recv = RangeSet::default();

        sent.union_mut(&(804..2100));
        sent.union_mut(&(3000..3910));

        recv.union_mut(&(0..1432));
        recv.union_mut(&(2000..2100));

        (sent, recv)
    }

    #[fixture]
    fn hash() -> (RangeSet<usize>, RangeSet<usize>) {
        let mut sent = RangeSet::default();
        let mut recv = RangeSet::default();

        sent.union_mut(&(100..2100));

        recv.union_mut(&(720..930));

        (sent, recv)
    }

    #[fixture]
    fn transcript() -> TlsTranscript {
        transcript_fixture()
    }

    #[fixture]
    fn transcript_refs(transcript: TlsTranscript) -> TranscriptRefs {
        let len_sent = transcript
            .iter_sent_app_data()
            .map(|record| record.ciphertext.len())
            .sum();
        let len_recv = transcript
            .iter_recv_app_data()
            .map(|record| record.ciphertext.len())
            .sum();

        TranscriptRefs::new(len_sent, len_recv)
    }
}
