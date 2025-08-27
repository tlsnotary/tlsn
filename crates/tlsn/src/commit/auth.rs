//! Authentication of the transcript plaintext and creation of the transcript
//! references.

use crate::{
    Role,
    commit::transcript::TranscriptRefs,
    zk_aes_ctr::{ZkAesCtr, ZkAesCtrError},
};
use mpz_memory_core::{
    Array, DecodeError, MemoryExt, ViewExt,
    binary::{Binary, U8},
};
use mpz_vm_core::Vm;
use rangeset::{Disjoint, RangeSet, Union, UnionMut};
use std::ops::Range;
use tlsn_core::{
    hash::HashAlgId,
    transcript::{Direction, Idx, PartialTranscript, Record, TlsTranscript},
};

/// Transcript Authenticator.
pub(crate) struct Authenticator {
    server_write_key: Array<U8, 16>,
    server_write_iv: Array<U8, 4>,
    encoding: Index,
    hash: Index,
    decoding: Index,
    proving: Index,
}

impl Authenticator {
    /// Creates a new authenticator.
    ///
    /// # Arguments
    ///
    /// * `server_write_key` - The server write key.
    /// * `server_write_iv` - The server write iv.
    /// * `encoding` - Ranges for encoding commitments.
    /// * `hash` - Ranges for hash commitments.
    /// * `partial` - The partial transcript.
    pub(crate) fn new<'a>(
        server_write_key: Array<U8, 16>,
        server_write_iv: Array<U8, 4>,
        encoding: impl Iterator<Item = &'a (Direction, Idx)>,
        hash: impl Iterator<Item = &'a (Direction, Idx, HashAlgId)>,
        partial: Option<&PartialTranscript>,
    ) -> Self {
        // Compute encoding index.
        let mut encoding_sent = RangeSet::default();
        let mut encoding_recv = RangeSet::default();

        for (d, idx) in encoding {
            match d {
                Direction::Sent => encoding_sent.union_mut(idx.as_range_set()),
                Direction::Received => encoding_recv.union_mut(idx.as_range_set()),
            }
        }

        let encoding = Index::new(encoding_sent, encoding_recv);

        // Compute hash index.
        let mut hash_sent = RangeSet::default();
        let mut hash_recv = RangeSet::default();

        for (d, idx, _) in hash {
            match d {
                Direction::Sent => hash_sent.union_mut(idx.as_range_set()),
                Direction::Received => hash_recv.union_mut(idx.as_range_set()),
            }
        }

        let hash = Index {
            sent: hash_sent,
            recv: hash_recv,
        };

        // Compute decoding index.
        let mut decoding_sent = RangeSet::default();
        let mut decoding_recv = RangeSet::default();

        if let Some(partial) = partial {
            decoding_sent.union_mut(partial.sent_authed().as_range_set());
            decoding_recv.union_mut(partial.received_authed().as_range_set());
        }

        let decoding = Index::new(decoding_sent, decoding_recv);

        // Compute proving index.
        let mut proving_sent = RangeSet::default();
        let mut proving_recv = RangeSet::default();

        proving_sent.union_mut(decoding.sent());
        proving_sent.union_mut(encoding.sent());
        proving_sent.union_mut(hash.sent());

        proving_recv.union_mut(decoding.recv());
        proving_recv.union_mut(encoding.recv());
        proving_recv.union_mut(hash.recv());

        let proving = Index::new(proving_sent, proving_recv);

        Self {
            server_write_key,
            server_write_iv,
            encoding,
            hash,
            decoding,
            proving,
        }
    }

    /// Authenticates the sent plaintext, returning a proof of encryption and
    /// writes the plaintext VM references to the transcript references.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine.
    /// * `zk_aes_sent` - ZK AES Cipher for sent traffic.
    /// * `transcript` - The TLS transcript.
    /// * `transcript_refs` - The transcript references.
    pub(crate) fn auth_sent(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        zk_aes_sent: &mut ZkAesCtr,
        transcript: &TlsTranscript,
        transcript_refs: &mut TranscriptRefs,
    ) -> Result<RecordProof, AuthError> {
        let missing_index = transcript_refs.compute_missing(Direction::Sent, self.proving.sent());

        // If there is nothing new to prove, return early.
        if missing_index == RangeSet::default() {
            return Ok(RecordProof::default());
        }

        authenticate_zk(
            vm,
            zk_aes_sent,
            Direction::Sent,
            transcript.iter_sent_app_data(),
            transcript_refs,
            missing_index,
        )
    }

    /// Authenticates the received plaintext, returning a proof of encryption
    /// and writes the plaintext VM references to the transcript references.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine.
    /// * `zk_aes_recv` - ZK AES Cipher for received traffic.
    /// * `transcript` - The TLS transcript.
    /// * `transcript_refs` - The transcript references.
    pub(crate) fn auth_recv(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        zk_aes_recv: &mut ZkAesCtr,
        transcript: &TlsTranscript,
        transcript_refs: &mut TranscriptRefs,
    ) -> Result<RecordProof, AuthError> {
        let proving_index = self.proving.recv();
        let missing_index = transcript_refs.compute_missing(Direction::Received, proving_index);

        // If there is nothing new to prove, return early.
        if missing_index == RangeSet::default() {
            return Ok(RecordProof::default());
        }

        // If possible use server write key for authentication.
        let decoding_index = self.decoding.recv();
        let fully_decoded = decoding_index.union(&transcript_refs.decoded(Direction::Received));

        let full_range = 0..transcript_refs.max_len(Direction::Received);

        if fully_decoded == full_range {
            return self.authenticate_swk(
                vm,
                zk_aes_recv.role(),
                transcript.iter_recv_app_data(),
                transcript_refs,
                &missing_index,
            );
        }

        authenticate_zk(
            vm,
            zk_aes_recv,
            Direction::Received,
            transcript.iter_recv_app_data(),
            transcript_refs,
            missing_index,
        )
    }

    /// Returns the sent and received encoding ranges.
    pub(crate) fn encoding(&self) -> (&RangeSet<usize>, &RangeSet<usize>) {
        (self.encoding.sent(), self.encoding.recv())
    }

    /// Returns the sent and received hash ranges.
    pub(crate) fn hash(&self) -> (&RangeSet<usize>, &RangeSet<usize>) {
        (self.hash.sent(), self.hash.recv())
    }

    /// Returns the sent and received decoding ranges.
    pub(crate) fn decoding(&self) -> (&RangeSet<usize>, &RangeSet<usize>) {
        (self.decoding.sent(), self.decoding.recv())
    }

    /// Authenticates parts of the received transcript using the server write
    /// key.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine.
    /// * `role` - The role.
    /// * `recv_app_data` - The received application data.
    /// * `transcript_refs` - The transcript references.
    /// * `missing_index` - The index which needs to be proven.
    fn authenticate_swk<'a>(
        &self,
        vm: &mut dyn Vm<Binary>,
        role: Role,
        recv_app_data: impl Iterator<Item = &'a Record>,
        transcript_refs: &mut TranscriptRefs,
        missing_index: &RangeSet<usize>,
    ) -> Result<RecordProof, AuthError> {
        let mut key = vm.decode(self.server_write_key).map_err(AuthError::vm)?;
        let mut iv = vm.decode(self.server_write_iv).map_err(AuthError::vm)?;

        let mut record_idx = Range::default();

        let mut ciphertexts = Vec::new();
        let mut plaintext_refs = Vec::new();
        let mut record_indices = Vec::new();
        let mut explicit_nonces = Vec::new();

        for record in recv_app_data {
            let record_len = record.ciphertext.len();
            record_idx.end += record_len;

            if missing_index.is_disjoint(&record_idx) {
                record_idx.start += record_len;
                continue;
            }
            let plaintext_ref = vm.alloc_vec(record_idx.len()).map_err(AuthError::vm)?;
            vm.mark_public(plaintext_ref).map_err(AuthError::vm)?;

            if let Role::Prover = role {
                let plaintext = record
                    .plaintext
                    .clone()
                    .expect("plaintext should be available for prover");
                vm.assign(plaintext_ref, plaintext).map_err(AuthError::vm)?;
                vm.commit(plaintext_ref).map_err(AuthError::vm)?;
            }

            transcript_refs.add(Direction::Received, &record_idx, plaintext_ref);

            ciphertexts.extend_from_slice(&record.ciphertext);
            plaintext_refs.push(plaintext_ref);
            record_indices.push(record_idx.clone());
            explicit_nonces.push(record.explicit_nonce.clone());

            record_idx.start += record_len;
        }

        let verify = move |vm: &mut dyn Vm<Binary>| {
            let key = key
                .try_recv()?
                .ok_or(AuthError(ErrorRepr::MissingDecoding))?;
            let iv = iv
                .try_recv()?
                .ok_or(AuthError(ErrorRepr::MissingDecoding))?;

            let mut current_pos = 0;
            for ((record_idx, explicit_nonce), plaintext_ref) in record_indices
                .iter()
                .zip(explicit_nonces)
                .zip(plaintext_refs)
            {
                let explicit_nonce: [u8; 8] = explicit_nonce
                    .try_into()
                    .expect("explicit nonce should be 8 bytes");
                let record_len = record_idx.len();
                let ciphertext = &ciphertexts[current_pos..current_pos + record_len];

                let plaintext = aes_apply_keystream(key, iv, explicit_nonce, ciphertext);

                vm.assign(plaintext_ref, plaintext).map_err(AuthError::vm)?;
                vm.commit(plaintext_ref).map_err(AuthError::vm)?;

                current_pos += record_len;
            }
            Ok(())
        };

        let proof = RecordProof {
            verify: Box::new(verify),
        };

        Ok(proof)
    }
}

/// Authenticates parts of the transcript in zk.
///
/// # Arguments
///
/// * `vm` - The virtual machine.
/// * `zk_aes` - ZK AES Cipher.
/// * `direction` - The direction of the application data.
/// * `app_data` - The application data.
/// * `transcript_refs` - The transcript references.
/// * `missing_index` - The index which needs to be proven.
fn authenticate_zk<'a>(
    vm: &mut dyn Vm<Binary>,
    zk_aes: &mut ZkAesCtr,
    direction: Direction,
    app_data: impl Iterator<Item = &'a Record>,
    transcript_refs: &mut TranscriptRefs,
    missing_index: RangeSet<usize>,
) -> Result<RecordProof, AuthError> {
    let mut record_idx = Range::default();
    let mut ciphertexts = Vec::new();

    for record in app_data {
        let record_len = record.ciphertext.len();
        record_idx.end += record_len;

        if missing_index.is_disjoint(&record_idx) {
            record_idx.start += record_len;
            continue;
        }

        let (plaintext_ref, ciphertext_ref) =
            zk_aes.encrypt(vm, record.explicit_nonce.clone(), record.ciphertext.len())?;

        if let Role::Prover = zk_aes.role() {
            let Some(plaintext) = record.plaintext.clone() else {
                return Err(AuthError(ErrorRepr::MissingPlainText));
            };

            vm.assign(plaintext_ref, plaintext).map_err(AuthError::vm)?;
        }
        vm.commit(plaintext_ref).map_err(AuthError::vm)?;

        let ciphertext = vm.decode(ciphertext_ref).map_err(AuthError::vm)?;

        transcript_refs.add(direction, &record_idx, plaintext_ref);
        ciphertexts.push((ciphertext, record.ciphertext.clone()));

        record_idx.start += record_len;
    }

    let verify = move |_: &mut dyn Vm<Binary>| {
        for (mut ciphertext, expected) in ciphertexts {
            let ciphertext = ciphertext
                .try_recv()?
                .ok_or(AuthError(ErrorRepr::MissingDecoding))?;

            if ciphertext != expected {
                return Err(AuthError(ErrorRepr::InvalidCiphertext));
            }
        }

        Ok(())
    };

    let proof = RecordProof {
        verify: Box::new(verify),
    };
    Ok(proof)
}

#[derive(Debug, Clone, Default)]
struct Index {
    sent: RangeSet<usize>,
    recv: RangeSet<usize>,
}

impl Index {
    fn new(sent: RangeSet<usize>, recv: RangeSet<usize>) -> Self {
        Self { sent, recv }
    }

    fn sent(&self) -> &RangeSet<usize> {
        &self.sent
    }

    fn recv(&self) -> &RangeSet<usize> {
        &self.recv
    }
}

/// Proof of encryption.
#[must_use]
pub(crate) struct RecordProof {
    verify: Box<VerifyRecords>,
}

impl Default for RecordProof {
    fn default() -> Self {
        Self {
            verify: Box::new(|_| Ok(())),
        }
    }
}

impl RecordProof {
    /// Verifies the proof.
    pub(crate) fn verify(self, vm: &mut dyn Vm<Binary>) -> Result<(), AuthError> {
        (self.verify)(vm)
    }
}

pub(crate) type VerifyRecords =
    dyn for<'a> FnOnce(&'a mut dyn Vm<Binary>) -> Result<(), AuthError> + Send;

fn aes_apply_keystream(key: [u8; 16], iv: [u8; 4], explicit_nonce: [u8; 8], msg: &[u8]) -> Vec<u8> {
    use aes::Aes128;
    use cipher_crypto::{KeyIvInit, StreamCipher, StreamCipherSeek};
    use ctr::Ctr32BE;

    let start_ctr = 2;
    let mut full_iv = [0u8; 16];
    full_iv[0..4].copy_from_slice(&iv);
    full_iv[4..12].copy_from_slice(&explicit_nonce);

    let mut cipher = Ctr32BE::<Aes128>::new(&key.into(), &full_iv.into());
    let mut out = msg.to_vec();

    cipher
        .try_seek(start_ctr * 16)
        .expect("start counter is less than keystream length");
    cipher.apply_keystream(&mut out);

    out
}

/// Error for [`Authenticator`].
#[derive(Debug, thiserror::Error)]
#[error("transcript authentication error: {0}")]
pub(crate) struct AuthError(#[source] ErrorRepr);

impl AuthError {
    fn vm<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Vm(err.into()))
    }
}

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("vm error: {0}")]
    Vm(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("zk-aes error: {0}")]
    ZkAes(ZkAesCtrError),
    #[error("decode error: {0}")]
    Decode(DecodeError),
    #[error("plaintext is missing in record")]
    MissingPlainText,
    #[error("decoded value is missing")]
    MissingDecoding,
    #[error("invalid ciphertext")]
    InvalidCiphertext,
}

impl From<ZkAesCtrError> for AuthError {
    fn from(value: ZkAesCtrError) -> Self {
        Self(ErrorRepr::ZkAes(value))
    }
}

impl From<DecodeError> for AuthError {
    fn from(value: DecodeError) -> Self {
        Self(ErrorRepr::Decode(value))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        Role,
        commit::{
            auth::{Authenticator, ErrorRepr},
            transcript::TranscriptRefs,
        },
        zk_aes_ctr::ZkAesCtr,
    };
    use mpz_common::context::test_st_context;
    use mpz_garble_core::Delta;
    use mpz_memory_core::{
        Array, MemoryExt, ViewExt,
        binary::{Binary, U8},
    };
    use mpz_ot::ideal::rcot::{IdealRCOTReceiver, IdealRCOTSender, ideal_rcot};
    use mpz_vm_core::{Execute, Vm};
    use mpz_zk::{Prover, Verifier};
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use rangeset::{RangeSet, UnionMut};
    use rstest::{fixture, rstest};
    use tlsn_core::{
        fixtures::{
            IV, KEY, RECORD_SIZE, RECV_LEN, SENT_LEN, forged_transcript, transcript_fixture,
        },
        hash::HashAlgId,
        transcript::{Direction, Idx, TlsTranscript},
    };

    #[rstest]
    #[tokio::test]
    async fn test_authenticator_sent(
        encoding: Vec<(Direction, Idx)>,
        hashes: Vec<(Direction, Idx, HashAlgId)>,
        decoding: (RangeSet<usize>, RangeSet<usize>),
        transcript: TlsTranscript,
        transcript_refs: TranscriptRefs,
    ) {
        let (sent_decdoding, recv_decdoding) = decoding;
        let partial = transcript
            .to_transcript()
            .unwrap()
            .to_partial(Idx::new(sent_decdoding), Idx::new(recv_decdoding));

        let (mut ctx_p, mut ctx_v) = test_st_context(8);

        let (mut prover, mut verifier) = vms();
        let mut refs_prover = transcript_refs.clone();
        let mut refs_verifier = transcript_refs;

        let (key, iv) = keys(&mut prover, KEY, IV, Role::Prover);
        let mut auth_prover =
            Authenticator::new(key, iv, encoding.iter(), hashes.iter(), Some(&partial));
        let mut zk_prover = ZkAesCtr::new(Role::Prover);
        zk_prover.set_key(key, iv);
        zk_prover.alloc(&mut prover, SENT_LEN).unwrap();

        let (key, iv) = keys(&mut verifier, KEY, IV, Role::Verifier);
        let mut auth_verifier =
            Authenticator::new(key, iv, encoding.iter(), hashes.iter(), Some(&partial));
        let mut zk_verifier = ZkAesCtr::new(Role::Verifier);
        zk_verifier.set_key(key, iv);
        zk_verifier.alloc(&mut verifier, SENT_LEN).unwrap();

        let _ = auth_prover
            .auth_sent(&mut prover, &mut zk_prover, &transcript, &mut refs_prover)
            .unwrap();

        let proof = auth_verifier
            .auth_sent(
                &mut verifier,
                &mut zk_verifier,
                &transcript,
                &mut refs_verifier,
            )
            .unwrap();

        tokio::try_join!(
            prover.execute_all(&mut ctx_p),
            verifier.execute_all(&mut ctx_v)
        )
        .unwrap();

        proof.verify(&mut verifier).unwrap();

        let mut prove_range: RangeSet<usize> = RangeSet::default();
        prove_range.union_mut(&(600..1600));
        prove_range.union_mut(&(800..2000));
        prove_range.union_mut(&(2600..3700));

        let mut expected_ranges = RangeSet::default();
        for r in prove_range.iter_ranges() {
            let floor = r.start / RECORD_SIZE;
            let ceil = r.end.div_ceil(RECORD_SIZE);

            let expected = floor * RECORD_SIZE..ceil * RECORD_SIZE;
            expected_ranges.union_mut(&expected);
        }

        assert_eq!(refs_prover.index(Direction::Sent), expected_ranges);
        assert_eq!(refs_verifier.index(Direction::Sent), expected_ranges);

        assert_eq!(refs_prover.decoded(Direction::Sent), RangeSet::default());
        assert_eq!(refs_verifier.decoded(Direction::Sent), RangeSet::default());
    }

    #[rstest]
    #[tokio::test]
    async fn test_authenticator_recv(
        encoding: Vec<(Direction, Idx)>,
        hashes: Vec<(Direction, Idx, HashAlgId)>,
        decoding: (RangeSet<usize>, RangeSet<usize>),
        transcript: TlsTranscript,
        transcript_refs: TranscriptRefs,
    ) {
        let (sent_decdoding, recv_decdoding) = decoding;
        let partial = transcript
            .to_transcript()
            .unwrap()
            .to_partial(Idx::new(sent_decdoding), Idx::new(recv_decdoding));

        let (mut ctx_p, mut ctx_v) = test_st_context(8);

        let (mut prover, mut verifier) = vms();
        let mut refs_prover = transcript_refs.clone();
        let mut refs_verifier = transcript_refs;

        let (key, iv) = keys(&mut prover, KEY, IV, Role::Prover);
        let mut auth_prover =
            Authenticator::new(key, iv, encoding.iter(), hashes.iter(), Some(&partial));
        let mut zk_prover = ZkAesCtr::new(Role::Prover);
        zk_prover.set_key(key, iv);
        zk_prover.alloc(&mut prover, RECV_LEN).unwrap();

        let (key, iv) = keys(&mut verifier, KEY, IV, Role::Verifier);
        let mut auth_verifier =
            Authenticator::new(key, iv, encoding.iter(), hashes.iter(), Some(&partial));
        let mut zk_verifier = ZkAesCtr::new(Role::Verifier);
        zk_verifier.set_key(key, iv);
        zk_verifier.alloc(&mut verifier, RECV_LEN).unwrap();

        let _ = auth_prover
            .auth_recv(&mut prover, &mut zk_prover, &transcript, &mut refs_prover)
            .unwrap();

        let proof = auth_verifier
            .auth_recv(
                &mut verifier,
                &mut zk_verifier,
                &transcript,
                &mut refs_verifier,
            )
            .unwrap();

        tokio::try_join!(
            prover.execute_all(&mut ctx_p),
            verifier.execute_all(&mut ctx_v)
        )
        .unwrap();

        proof.verify(&mut verifier).unwrap();

        let mut prove_range: RangeSet<usize> = RangeSet::default();

        prove_range.union_mut(&(4000..4200));
        prove_range.union_mut(&(5000..5800));
        prove_range.union_mut(&(6800..RECV_LEN));

        let mut expected_ranges = RangeSet::default();
        for r in prove_range.iter_ranges() {
            let floor = r.start / RECORD_SIZE;
            let ceil = r.end.div_ceil(RECORD_SIZE);

            let expected = floor * RECORD_SIZE..ceil * RECORD_SIZE;
            expected_ranges.union_mut(&expected);
        }

        assert_eq!(refs_prover.index(Direction::Received), expected_ranges);
        assert_eq!(refs_verifier.index(Direction::Received), expected_ranges);

        assert_eq!(
            refs_prover.decoded(Direction::Received),
            RangeSet::default()
        );
        assert_eq!(
            refs_verifier.decoded(Direction::Received),
            RangeSet::default()
        );
    }

    #[rstest]
    #[tokio::test]
    async fn test_authenticator_sent_verify_fail(
        encoding: Vec<(Direction, Idx)>,
        hashes: Vec<(Direction, Idx, HashAlgId)>,
        decoding: (RangeSet<usize>, RangeSet<usize>),
        transcript: TlsTranscript,
        transcript_refs: TranscriptRefs,
    ) {
        let (sent_decdoding, recv_decdoding) = decoding;
        let partial = transcript
            .to_transcript()
            .unwrap()
            .to_partial(Idx::new(sent_decdoding), Idx::new(recv_decdoding));

        let (mut ctx_p, mut ctx_v) = test_st_context(8);

        let (mut prover, mut verifier) = vms();
        let mut refs_prover = transcript_refs.clone();
        let mut refs_verifier = transcript_refs;

        let (key, iv) = keys(&mut prover, KEY, IV, Role::Prover);
        let mut auth_prover =
            Authenticator::new(key, iv, encoding.iter(), hashes.iter(), Some(&partial));
        let mut zk_prover = ZkAesCtr::new(Role::Prover);
        zk_prover.set_key(key, iv);
        zk_prover.alloc(&mut prover, SENT_LEN).unwrap();

        let (key, iv) = keys(&mut verifier, KEY, IV, Role::Verifier);
        let mut auth_verifier =
            Authenticator::new(key, iv, encoding.iter(), hashes.iter(), Some(&partial));
        let mut zk_verifier = ZkAesCtr::new(Role::Verifier);
        zk_verifier.set_key(key, iv);
        zk_verifier.alloc(&mut verifier, SENT_LEN).unwrap();

        let _ = auth_prover
            .auth_sent(&mut prover, &mut zk_prover, &transcript, &mut refs_prover)
            .unwrap();

        // Forge verifier transcript to check if verify fails.
        // Use an index which is part of the proving range.
        let forged = forged_transcript(Direction::Sent, 610);

        let proof = auth_verifier
            .auth_sent(&mut verifier, &mut zk_verifier, &forged, &mut refs_verifier)
            .unwrap();

        tokio::try_join!(
            prover.execute_all(&mut ctx_p),
            verifier.execute_all(&mut ctx_v)
        )
        .unwrap();

        let err = proof.verify(&mut verifier).unwrap_err();
        assert!(matches!(err.0, ErrorRepr::InvalidCiphertext));
    }

    #[rstest]
    #[tokio::test]
    async fn test_authenticator_recv_with_swk(
        encoding: Vec<(Direction, Idx)>,
        hashes: Vec<(Direction, Idx, HashAlgId)>,
        full_decoding: (RangeSet<usize>, RangeSet<usize>),
        transcript: TlsTranscript,
        transcript_refs: TranscriptRefs,
    ) {
        let (sent_decdoding, recv_decdoding) = full_decoding;
        let partial = transcript
            .to_transcript()
            .unwrap()
            .to_partial(Idx::new(sent_decdoding), Idx::new(recv_decdoding));

        let (mut ctx_p, mut ctx_v) = test_st_context(8);

        let (mut prover, mut verifier) = vms();
        let mut refs_prover = transcript_refs.clone();
        let mut refs_verifier = transcript_refs;

        let (key, iv) = keys(&mut prover, KEY, IV, Role::Prover);
        let mut auth_prover =
            Authenticator::new(key, iv, encoding.iter(), hashes.iter(), Some(&partial));
        let mut zk_prover = ZkAesCtr::new(Role::Prover);
        zk_prover.set_key(key, iv);
        zk_prover.alloc(&mut prover, RECV_LEN).unwrap();

        let (key, iv) = keys(&mut verifier, KEY, IV, Role::Verifier);
        let mut auth_verifier =
            Authenticator::new(key, iv, encoding.iter(), hashes.iter(), Some(&partial));
        let mut zk_verifier = ZkAesCtr::new(Role::Verifier);
        zk_verifier.set_key(key, iv);
        zk_verifier.alloc(&mut verifier, RECV_LEN).unwrap();

        let _ = auth_prover
            .auth_recv(&mut prover, &mut zk_prover, &transcript, &mut refs_prover)
            .unwrap();

        let proof = auth_verifier
            .auth_recv(
                &mut verifier,
                &mut zk_verifier,
                &transcript,
                &mut refs_verifier,
            )
            .unwrap();

        tokio::try_join!(
            prover.execute_all(&mut ctx_p),
            verifier.execute_all(&mut ctx_v)
        )
        .unwrap();

        proof.verify(&mut verifier).unwrap();

        let expected_ranges: RangeSet<usize> = (0..RECV_LEN).into();
        assert_eq!(refs_prover.index(Direction::Received), expected_ranges);
        assert_eq!(refs_verifier.index(Direction::Received), expected_ranges);

        assert_eq!(
            refs_prover.decoded(Direction::Received),
            RangeSet::default()
        );
        assert_eq!(
            refs_verifier.decoded(Direction::Received),
            RangeSet::default()
        );

        let plaintext_recovered_prover =
            refs_prover.get(Direction::Received, &(0..RECV_LEN).into())[0];
        let plaintext_recovered_verifier =
            refs_verifier.get(Direction::Received, &(0..RECV_LEN).into())[0];

        let mut plaintext_prover = prover.decode(plaintext_recovered_prover).unwrap();
        let mut plaintext_verifier = verifier.decode(plaintext_recovered_verifier).unwrap();

        tokio::try_join!(
            prover.execute_all(&mut ctx_p),
            verifier.execute_all(&mut ctx_v)
        )
        .unwrap();

        let plaintext_prover = plaintext_prover.try_recv().unwrap().unwrap();
        let plaintext_verifier = plaintext_verifier.try_recv().unwrap().unwrap();

        assert_eq!(plaintext_prover, plaintext_verifier);
        assert_eq!(plaintext_prover.len(), RECV_LEN);
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
    fn decoding() -> (RangeSet<usize>, RangeSet<usize>) {
        let sent = 600..1600;
        let recv = 4000..4200;

        (sent.into(), recv.into())
    }

    #[fixture]
    fn full_decoding() -> (RangeSet<usize>, RangeSet<usize>) {
        let sent = 600..1600;
        let recv = 0..RECV_LEN;

        (sent.into(), recv.into())
    }

    #[fixture]
    fn encoding() -> Vec<(Direction, Idx)> {
        let sent = Idx::new(800..2000);
        let recv = Idx::new(5000..5800);

        let encoding = vec![(Direction::Sent, sent), (Direction::Received, recv)];
        encoding
    }

    #[fixture]
    fn hashes() -> Vec<(Direction, Idx, HashAlgId)> {
        let sent = Idx::new(2600..3700);
        let recv = Idx::new(6800..RECV_LEN);

        let alg = HashAlgId::SHA256;

        let hashes = vec![
            (Direction::Sent, sent, alg),
            (Direction::Received, recv, alg),
        ];
        hashes
    }

    fn vms() -> (Prover<IdealRCOTReceiver>, Verifier<IdealRCOTSender>) {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (ot_send, ot_recv) = ideal_rcot(rng.random(), delta.into_inner());

        let prover = Prover::new(ot_recv);
        let verifier = Verifier::new(delta, ot_send);

        (prover, verifier)
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
