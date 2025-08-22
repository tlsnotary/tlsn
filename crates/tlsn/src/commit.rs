//! Proving flow for prover and verifier. Handles necessary parts for commitment
//! creation.
//!
//! - transcript reference storage in [`transcript`]
//! - transcript's plaintext authentication in [`auth`]
//! - check of server identity [`ProvingState::verify_server_identity`]
//! - selective disclosure [`ProvingState::decode_transcript`] and
//!   [`ProvingState::verify_transcript`]
//! - creation of encoding commitments in [`encoding`]
//! - creation of hash commitments in [`hash`]

pub(crate) mod auth;
pub(crate) mod encoding;
pub(crate) mod hash;
pub(crate) mod transcript;

use crate::{
    EncodingVm,
    commit::{
        auth::{AuthError, Authenticator},
        encoding::{ENCODING_SIZE, EncodingCreator},
        hash::{HashCommitError, HashFuture, PlaintextHasher},
        transcript::TranscriptRefs,
    },
    mux::MuxFuture,
    zk_aes_ctr::ZkAesCtr,
};
use encoding::{EncodingError, Encodings};
use futures::TryFutureExt;
use mpc_tls::SessionKeys;
use mpz_common::Context;
use mpz_garble_core::Delta;
use mpz_memory_core::binary::Binary;
use mpz_vm_core::{Vm, VmError, prelude::*};
use serio::{SinkExt, stream::IoStreamExt};
use tlsn_core::{
    ProveConfig, ProvePayload, ProverOutput, VerifierOutput,
    connection::{HandshakeData, HandshakeVerificationError, ServerName},
    hash::HashAlgId,
    transcript::{
        Direction, Idx, PartialTranscript, TlsTranscript, TranscriptCommitment, TranscriptSecret,
        encoding::{EncoderSecret, EncodingCommitment, EncodingTree},
    },
    webpki::{RootCertStore, ServerCertVerifier, ServerCertVerifierError},
};

/// Internal proving state used by [`Prover`](crate::prover::Prover) and
/// [`Verifier`](crate::verifier::Verifier).
///
/// Manages the prover and verifier flow. Performs transcript decoding and
/// delegates transcript authentication to [`Authenticator`] and commitments to
/// [`EncodingCreator`] and [`PlaintextHasher`].
pub(crate) struct ProvingState<'a> {
    partial: Option<PartialTranscript>,

    server_identity: Option<(ServerName, HandshakeData)>,
    verified_server_name: Option<ServerName>,

    authenticator: Authenticator,
    encoding: EncodingCreator,
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
    /// * `keys` - The session keys.
    /// * `transcript` - The TLS transcript.
    /// * `transcript_refs` - The transcript references.
    pub(crate) fn for_prover(
        config: ProveConfig,
        keys: SessionKeys,
        transcript: &'a TlsTranscript,
        transcript_refs: &'a mut TranscriptRefs,
    ) -> Self {
        let commit_config = config.transcript_commit();

        let mut encoding_hash_id = None;
        let mut encoding_ranges: Vec<(Direction, Idx)> = Vec::new();
        let mut hash_ranges: Vec<(Direction, Idx, HashAlgId)> = Vec::new();

        if let Some(commit_config) = commit_config {
            encoding_hash_id = Some(*commit_config.encoding_hash_alg());

            encoding_ranges = commit_config
                .iter_encoding()
                .map(|(dir, idx)| (*dir, idx.clone()))
                .collect();
            hash_ranges = commit_config
                .iter_hash()
                .map(|((dir, idx), alg)| (*dir, idx.clone(), *alg))
                .collect();
        }

        let partial = config.into_transcript();
        let authenticator = Authenticator::new(
            keys.server_write_key,
            keys.server_write_iv,
            encoding_ranges.iter(),
            hash_ranges.iter(),
            partial.as_ref(),
        );

        let (encoding_sent, encoding_recv) = authenticator.encoding();
        let encoding = EncodingCreator::new(
            encoding_hash_id,
            encoding_sent.clone(),
            encoding_recv.clone(),
        );

        let hasher = PlaintextHasher::new(hash_ranges.iter());

        Self {
            partial,
            server_identity: None,
            verified_server_name: None,
            authenticator,
            encoding,
            hasher,
            transcript,
            transcript_refs,
        }
    }

    /// Proves the transcript and generates the prover output.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine.
    /// * `muxer` - The multiplexer future.
    /// * `ctx` - The thread context.
    /// * `zk_aes_sent` - ZkAes for the sent traffic.
    /// * `zk_aes_recv` - ZkAes for the received traffic.
    pub(crate) async fn prove(
        &mut self,
        vm: &mut (dyn EncodingVm<Binary> + Send),
        muxer: &mut MuxFuture,
        ctx: &mut Context,
        zk_aes_sent: &mut ZkAesCtr,
        zk_aes_recv: &mut ZkAesCtr,
    ) -> Result<ProverOutput, CommitError> {
        // Authenticate only necessary parts of the transcript. Proof is not needed on
        // the prover side.
        let _ =
            self.authenticator
                .auth_sent(vm, zk_aes_sent, self.transcript, self.transcript_refs)?;
        let _ =
            self.authenticator
                .auth_recv(vm, zk_aes_recv, self.transcript, self.transcript_refs)?;

        muxer
            .poll_with(vm.execute_all(ctx).map_err(CommitError::from))
            .await?;

        // Decode the transcript parts that should be disclosed.
        self.decode_transcript(vm)?;

        let mut output = ProverOutput::default();
        if self.has_encoding_ranges() {
            let (commitment, secret) = self.receive_encodings(vm, muxer, ctx).await?;

            output
                .transcript_commitments
                .push(TranscriptCommitment::Encoding(commitment));
            output
                .transcript_secrets
                .push(TranscriptSecret::Encoding(secret));
        }

        // Create hash commitments if necessary.
        let hash_output = if self.has_hash_ranges() {
            Some(self.hasher.prove(vm, &self.transcript_refs)?)
        } else {
            None
        };

        muxer
            .poll_with(vm.execute_all(ctx).map_err(CommitError::from))
            .await?;

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

        Ok(output)
    }

    pub(crate) fn verify(&mut self) -> Result<VerifierOutput, CommitError> {
        todo!()
    }

    /// Creates a new proving state for the verifier.
    ///
    /// # Arguments
    ///
    /// * `payload` - The prove payload.
    /// * `keys` - The session keys.
    /// * `transcript` - The TLS transcript.
    /// * `transcript_refs` - The transcript references.
    pub(crate) fn for_verifier(
        payload: ProvePayload,
        keys: SessionKeys,
        transcript: &'a TlsTranscript,
        transcript_refs: &'a mut TranscriptRefs,
    ) -> Self {
        let commit_config = payload.transcript_commit.as_ref();

        let mut encoding_ranges: Vec<(Direction, Idx)> = Vec::new();
        let mut hash_ranges: Vec<(Direction, Idx, HashAlgId)> = Vec::new();

        if let Some(commit_config) = commit_config {
            encoding_ranges = commit_config.iter_encoding().cloned().collect();
            hash_ranges = commit_config.iter_hash().cloned().collect();
        }

        let authenticator = Authenticator::new(
            keys.server_write_key,
            keys.server_write_iv,
            encoding_ranges.iter(),
            hash_ranges.iter(),
            payload.transcript.as_ref(),
        );

        let (encoding_sent, encoding_recv) = authenticator.encoding();
        let encoding = EncodingCreator::new(None, encoding_sent.clone(), encoding_recv.clone());

        let hasher = PlaintextHasher::new(hash_ranges.iter());

        Self {
            partial: payload.transcript,
            server_identity: payload.handshake,
            verified_server_name: None,

            authenticator,
            encoding,
            hasher,
            transcript,
            transcript_refs,
        }
    }

    /// Decodes parts of the transcript for selective disclosure.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine.
    pub(crate) fn decode_transcript(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), CommitError> {
        if self.has_decoding_ranges() {
            let (sent, recv) = self.authenticator.decoding();

            let sent_refs = self.transcript_refs.get(Direction::Sent, sent);
            let recv_refs = self.transcript_refs.get(Direction::Received, recv);

            for slice in sent_refs.into_iter().chain(recv_refs) {
                // Drop the future, we don't need it.
                drop(vm.decode(slice).map_err(CommitError::from));
            }

            self.transcript_refs.mark_decoded(Direction::Sent, sent);
            self.transcript_refs.mark_decoded(Direction::Received, recv);
        }

        Ok(())
    }

    /// Verifies parts of the transcript when doing selective disclosure.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine.
    pub(crate) fn verify_transcript(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), CommitError> {
        let Some(partial) = &self.partial else {
            return Err(CommitError(ErrorRepr::MissingPartialTranscript));
        };

        let (sent, recv) = self.authenticator.decoding();

        let sent_refs = self.transcript_refs.get(Direction::Sent, sent);
        let recv_refs = self.transcript_refs.get(Direction::Received, recv);

        let mut authenticated_data = Vec::new();
        for data in sent_refs.into_iter().chain(recv_refs) {
            let plaintext = vm
                .get(data)
                .expect("reference is valid")
                .expect("plaintext is decoded");
            authenticated_data.extend_from_slice(&plaintext);
        }

        let mut purported_data = Vec::with_capacity(authenticated_data.len());

        for range in sent.iter_ranges() {
            purported_data.extend_from_slice(&partial.sent_unsafe()[range]);
        }
        for range in recv.iter_ranges() {
            purported_data.extend_from_slice(&partial.received_unsafe()[range]);
        }

        if purported_data != authenticated_data {
            return Err(CommitError(ErrorRepr::InconsistentTranscript));
        }

        Ok(())
    }

    /// Checks the transcript length.
    pub(crate) fn check_transcript_length(&self) -> Result<(), CommitError> {
        let Some(partial) = &self.partial else {
            return Err(CommitError(ErrorRepr::MissingPartialTranscript));
        };
        let sent_len: usize = self
            .transcript
            .iter_sent_app_data()
            .map(|record| record.ciphertext.len())
            .sum();

        let recv_len: usize = self
            .transcript
            .iter_recv_app_data()
            .map(|record| record.ciphertext.len())
            .sum();

        // Check ranges.
        if partial.len_sent() != sent_len || partial.len_received() != recv_len {
            return Err(CommitError(ErrorRepr::VerifyTranscriptLength));
        }

        Ok(())
    }

    /// Checks the server identity.
    ///
    /// # Arguments
    ///
    /// * `root_store` - Contains root certificates.
    pub(crate) fn verify_server_identity(
        &mut self,
        root_store: Option<&RootCertStore>,
    ) -> Result<(), CommitError> {
        let Some((server_name, handshake_data)) = self.server_identity.as_ref() else {
            return Err(CommitError(ErrorRepr::MissingCertChain));
        };

        let verifier = if let Some(root_store) = root_store {
            ServerCertVerifier::new(root_store)
                .map_err(|err| CommitError(ErrorRepr::CertVerifier(err)))?
        } else {
            ServerCertVerifier::mozilla()
        };

        let time = self.transcript.time();
        let ephemeral_key = self.transcript.server_ephemeral_key();

        handshake_data
            .verify(&verifier, time, ephemeral_key, server_name)
            .map_err(|err| CommitError(ErrorRepr::VerifyServerName(err)))?;

        self.verified_server_name = Some(server_name.clone());
        Ok(())
    }

    /// Compute the encoding adjustments to send to the prover.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine.
    /// * `delta` - The Delta.
    pub(crate) fn transfer_encodings<'b>(
        &mut self,
        vm: &mut dyn EncodingVm<Binary>,
        delta: &Delta,
    ) -> Result<(Encodings, EncoderSecret), CommitError> {
        todo!()
    }

    /// Receive the encoding adjustments from the verifier and adjust the prover
    /// encodings.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine.
    /// * `muxer` - The multiplexer future.
    /// * `ctx` - The thread context.
    async fn receive_encodings<'b>(
        &mut self,
        vm: &mut dyn EncodingVm<Binary>,
        muxer: &mut MuxFuture,
        ctx: &mut Context,
    ) -> Result<(EncodingCommitment, EncodingTree), CommitError> {
        let frame_limit = self.encoding_size() + ctx.io().limit();

        let encodings: Encodings = muxer
            .poll_with(
                ctx.io_mut()
                    .with_limit(frame_limit)
                    .expect_next()
                    .map_err(CommitError::from),
            )
            .await?;

        let (root, tree) = self.encoding.receive(vm, encodings, self.transcript_refs)?;

        muxer
            .poll_with(ctx.io_mut().send(root).map_err(CommitError::from))
            .await?;
        let secret: EncoderSecret = muxer
            .poll_with(ctx.io_mut().expect_next().map_err(CommitError::from))
            .await?;

        let commitment = EncodingCommitment { root, secret };
        Ok((commitment, tree))
    }

    pub(crate) fn encoding_size(&self) -> usize {
        let (sent, recv) = self.authenticator.encoding();
        ENCODING_SIZE * (sent.len() + recv.len())
    }

    /// Verifies the prover's plaintext hashes.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine.
    pub(crate) fn verify_hashes(
        &mut self,
        vm: &mut dyn Vm<Binary>,
    ) -> Result<HashFuture, CommitError> {
        self.hasher
            .verify(vm, self.transcript_refs)
            .map_err(CommitError::from)
    }

    /// Returns if there are encoding ranges present.
    pub(crate) fn has_encoding_ranges(&self) -> bool {
        let (sent, recv) = self.authenticator.encoding();
        !sent.is_empty() || !recv.is_empty()
    }

    /// Returns if there are hash ranges present.
    pub(crate) fn has_hash_ranges(&self) -> bool {
        let (sent, recv) = self.authenticator.hash();
        !sent.is_empty() || !recv.is_empty()
    }

    /// Returns if there are decoding ranges present.
    pub(crate) fn has_decoding_ranges(&self) -> bool {
        let (sent, recv) = self.authenticator.decoding();
        !sent.is_empty() || !recv.is_empty()
    }

    /// Returns if there is a server idendity present.
    pub(crate) fn has_server_identity(&self) -> bool {
        self.server_identity.is_some()
    }
}

/// Error for [`RecordProof`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct CommitError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
#[error("record proof error: {0}")]
enum ErrorRepr {
    #[error("VM error: {0}")]
    Vm(VmError),
    #[error("IO error: {0}")]
    Io(std::io::Error),
    #[error("hash commit error: {0}")]
    Hash(HashCommitError),
    #[error("encoding error: {0}")]
    Encoding(EncodingError),
    #[error("authentication error: {0}")]
    Auth(AuthError),
    #[error("cert chain missing for verifying server identity")]
    MissingCertChain,
    #[error("missing partial transcript")]
    MissingPartialTranscript,
    #[error("failed to verify server name")]
    VerifyServerName(HandshakeVerificationError),
    #[error("cert verifier error: {0}")]
    CertVerifier(ServerCertVerifierError),
    #[error("length of partial transcript does not match expected length")]
    VerifyTranscriptLength,
    #[error("provided transcript does not match exptected")]
    InconsistentTranscript,
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

impl From<HashCommitError> for CommitError {
    fn from(value: HashCommitError) -> Self {
        CommitError(ErrorRepr::Hash(value))
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
    use mpz_vm_core::Vm;
    use mpz_zk::{Prover, Verifier};
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use rangeset::{RangeSet, UnionMut};
    use rstest::{fixture, rstest};
    use tlsn_core::{
        ProveConfig, ProvePayload,
        fixtures::{IV, KEY, RECV_LEN, SENT_LEN, transcript_fixture},
        transcript::{Direction, TlsTranscript},
    };

    use crate::{
        Role,
        commit::{ProvingState, transcript::TranscriptRefs},
        zk_aes_ctr::ZkAesCtr,
    };

    #[tokio::main]
    #[rstest]
    async fn test_decoding(
        vms: (impl Vm<Binary> + Send, impl Vm<Binary> + Send),
        decoding: (RangeSet<usize>, RangeSet<usize>),
        transcript: TlsTranscript,
        transcript_refs: TranscriptRefs,
        prove_config: ProveConfig,
        prove_payload: ProvePayload,
    ) {
        let (mut ctx_p, mut ctx_v) = test_st_context(8);

        let (mut prover, mut verifier) = vms;
        let mut refs_prover = transcript_refs.clone();
        let mut refs_verifier = transcript_refs;

        {
            let keys_prover = keys(&mut prover, KEY, IV, Role::Prover);
            // not needed
            let mac_key_prover = prover.alloc().unwrap();

            let session_keys_prover = SessionKeys {
                client_write_key: keys_prover.0,
                client_write_iv: keys_prover.1,
                server_write_key: keys_prover.0,
                server_write_iv: keys_prover.1,
                server_write_mac_key: mac_key_prover,
            };

            let keys_verifier = keys(&mut verifier, KEY, IV, Role::Verifier);
            // not needed
            let mac_key_verifier = verifier.alloc().unwrap();

            let session_keys_verifier = SessionKeys {
                client_write_key: keys_verifier.0,
                client_write_iv: keys_verifier.1,
                server_write_key: keys_verifier.0,
                server_write_iv: keys_verifier.1,
                server_write_mac_key: mac_key_verifier,
            };

            let mut prover_state = ProvingState::for_prover(
                prove_config,
                session_keys_prover,
                &transcript,
                &mut refs_prover,
            );

            let mut zk_prover_sent = ZkAesCtr::new(Role::Prover);
            zk_prover_sent.set_key(keys_prover.0, keys_prover.1);
            zk_prover_sent.alloc(&mut prover, SENT_LEN).unwrap();

            let mut zk_prover_recv = ZkAesCtr::new(Role::Prover);
            zk_prover_recv.set_key(keys_prover.0, keys_prover.1);
            zk_prover_recv.alloc(&mut prover, RECV_LEN).unwrap();

            let mut verifier_state = ProvingState::for_verifier(
                prove_payload,
                session_keys_verifier,
                &transcript,
                &mut refs_verifier,
            );

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

            _ = prover_state
                .auth_sent(&mut prover, &mut zk_prover_sent)
                .unwrap();
            _ = prover_state
                .auth_recv(&mut prover, &mut zk_prover_recv)
                .unwrap();

            let proof_sent = verifier_state
                .auth_sent(&mut verifier, &mut zk_verifier_sent)
                .unwrap();
            let proof_recv = verifier_state
                .auth_recv(&mut verifier, &mut zk_verifier_recv)
                .unwrap();

            tokio::try_join!(
                prover.execute_all(&mut ctx_p),
                verifier.execute_all(&mut ctx_v)
            )
            .unwrap();

            proof_sent.verify(&mut verifier).unwrap();
            proof_recv.verify(&mut verifier).unwrap();

            prover_state.decode_transcript(&mut prover).unwrap();
            verifier_state.decode_transcript(&mut verifier).unwrap();

            tokio::try_join!(
                prover.execute_all(&mut ctx_p),
                verifier.execute_all(&mut ctx_v)
            )
            .unwrap();

            verifier_state.verify_transcript(&mut verifier).unwrap();
        }

        assert_eq!(refs_prover.decoded(Direction::Sent), decoding.0);
        assert_eq!(refs_verifier.decoded(Direction::Sent), decoding.0);

        assert_eq!(refs_prover.decoded(Direction::Received), decoding.1);
        assert_eq!(refs_verifier.decoded(Direction::Received), decoding.1);
    }

    #[fixture]
    fn prove_config(
        decoding: (RangeSet<usize>, RangeSet<usize>),
        transcript: TlsTranscript,
    ) -> ProveConfig {
        let (sent, recv) = decoding;

        let transcript = transcript.to_transcript().unwrap();
        let mut builder = ProveConfig::builder(&transcript);

        builder.reveal_sent(&sent).unwrap();
        builder.reveal_recv(&recv).unwrap();

        builder.build().unwrap()
    }

    #[fixture]
    fn prove_payload(prove_config: ProveConfig) -> ProvePayload {
        ProvePayload::new(&prove_config, None)
    }

    fn keys(
        vm: &mut dyn Vm<Binary>,
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
    fn vms() -> (impl Vm<Binary> + Send, impl Vm<Binary> + Send) {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (ot_send, ot_recv) = ideal_rcot(rng.random(), delta.into_inner());

        let prover = Prover::new(ot_recv);
        let verifier = Verifier::new(delta, ot_send);

        (prover, verifier)
    }

    #[fixture]
    fn decoding() -> (RangeSet<usize>, RangeSet<usize>) {
        let mut sent = RangeSet::default();
        let mut recv = RangeSet::default();

        sent.union_mut(&(600..1100));
        sent.union_mut(&(3450..4000));

        recv.union_mut(&(2000..3000));
        recv.union_mut(&(4800..4900));
        recv.union_mut(&(6000..7000));

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
