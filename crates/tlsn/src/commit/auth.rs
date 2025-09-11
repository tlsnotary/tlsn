//! Authentication of the transcript plaintext and creation of the transcript
//! references.

use crate::{
    Role,
    commit::transcript::TranscriptRefs,
    zk_aes_ctr::{ZkAesCtr, ZkAesCtrError},
};
use mpz_core::bitvec::BitVec;
use mpz_memory_core::{DecodeError, DecodeFutureTyped, MemoryExt, binary::Binary};
use mpz_vm_core::Vm;
use rangeset::{Disjoint, RangeSet, Union, UnionMut};
use std::ops::Range;
use tlsn_core::{
    hash::HashAlgId,
    transcript::{ContentType, Direction, PartialTranscript, Record, TlsTranscript},
};

/// Transcript Authenticator.
pub(crate) struct Authenticator {
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
    /// * `encoding` - Ranges for encoding commitments.
    /// * `hash` - Ranges for hash commitments.
    /// * `partial` - The partial transcript.
    pub(crate) fn new<'a>(
        encoding: impl Iterator<Item = &'a (Direction, RangeSet<usize>)>,
        hash: impl Iterator<Item = &'a (Direction, RangeSet<usize>, HashAlgId)>,
        partial: Option<&PartialTranscript>,
    ) -> Self {
        // Compute encoding index.
        let mut encoding_sent = RangeSet::default();
        let mut encoding_recv = RangeSet::default();

        for (d, idx) in encoding {
            match d {
                Direction::Sent => encoding_sent.union_mut(idx),
                Direction::Received => encoding_recv.union_mut(idx),
            }
        }

        let encoding = Index::new(encoding_sent, encoding_recv);

        // Compute hash index.
        let mut hash_sent = RangeSet::default();
        let mut hash_recv = RangeSet::default();

        for (d, idx, _) in hash {
            match d {
                Direction::Sent => hash_sent.union_mut(idx),
                Direction::Received => hash_recv.union_mut(idx),
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
            decoding_sent.union_mut(partial.sent_authed());
            decoding_recv.union_mut(partial.received_authed());
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

        let sent = transcript
            .sent()
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData);

        authenticate(
            vm,
            zk_aes_sent,
            Direction::Sent,
            sent,
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
        let decoding_recv = self.decoding.recv();
        let fully_decoded = decoding_recv.union(&transcript_refs.decoded(Direction::Received));
        let full_range = 0..transcript_refs.max_len(Direction::Received);

        // If we only have decoding ranges, and the parts we are going to decode will
        // complete to the full received transcript, then we do not need to
        // authenticate, because this will be done by
        // `crate::commit::decode::verify_transcript`, as it uses the server write
        // key and iv for verification.
        if decoding_recv == self.proving.recv() && fully_decoded == full_range {
            return Ok(RecordProof::default());
        }

        let missing_index =
            transcript_refs.compute_missing(Direction::Received, self.proving.recv());

        // If there is nothing new to prove, return early.
        if missing_index == RangeSet::default() {
            return Ok(RecordProof::default());
        }

        let recv = transcript
            .recv()
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData);

        authenticate(
            vm,
            zk_aes_recv,
            Direction::Received,
            recv,
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
fn authenticate<'a>(
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

    let proof = RecordProof { ciphertexts };
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
#[derive(Debug, Default)]
#[must_use]
#[allow(clippy::type_complexity)]
pub(crate) struct RecordProof {
    ciphertexts: Vec<(DecodeFutureTyped<BitVec, Vec<u8>>, Vec<u8>)>,
}

impl RecordProof {
    /// Verifies the proof.
    pub(crate) fn verify(self) -> Result<(), AuthError> {
        let Self { ciphertexts } = self;

        for (mut ciphertext, expected) in ciphertexts {
            let ciphertext = ciphertext
                .try_recv()
                .map_err(AuthError::vm)?
                .ok_or(AuthError(ErrorRepr::MissingDecoding))?;

            if ciphertext != expected {
                return Err(AuthError(ErrorRepr::InvalidCiphertext));
            }
        }

        Ok(())
    }
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
    use lipsum::{LIBER_PRIMUS, lipsum};
    use mpz_common::context::test_st_context;
    use mpz_garble_core::Delta;
    use mpz_memory_core::{
        Array, MemoryExt, ViewExt,
        binary::{Binary, U8},
    };
    use mpz_ot::ideal::rcot::{IdealRCOTReceiver, IdealRCOTSender, ideal_rcot};
    use mpz_vm_core::{Execute, Vm};
    use mpz_zk::{Prover, ProverConfig, Verifier, VerifierConfig};
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use rangeset::{RangeSet, UnionMut};
    use rstest::{fixture, rstest};
    use tlsn_core::{
        fixtures::transcript::{IV, KEY, RECORD_SIZE},
        hash::HashAlgId,
        transcript::{ContentType, Direction, TlsTranscript},
    };

    #[rstest]
    #[tokio::test]
    async fn test_authenticator_sent(
        encoding: Vec<(Direction, RangeSet<usize>)>,
        hashes: Vec<(Direction, RangeSet<usize>, HashAlgId)>,
        decoding: (RangeSet<usize>, RangeSet<usize>),
        transcript: TlsTranscript,
        transcript_refs: TranscriptRefs,
    ) {
        let (sent_decdoding, recv_decdoding) = decoding;
        let partial = transcript
            .to_transcript()
            .unwrap()
            .to_partial(sent_decdoding, recv_decdoding);

        let (mut ctx_p, mut ctx_v) = test_st_context(8);

        let (mut prover, mut verifier) = vms();
        let mut refs_prover = transcript_refs.clone();
        let mut refs_verifier = transcript_refs;

        let (key, iv) = keys(&mut prover, KEY, IV, Role::Prover);
        let mut auth_prover = Authenticator::new(encoding.iter(), hashes.iter(), Some(&partial));
        let mut zk_prover = ZkAesCtr::new(Role::Prover);
        zk_prover.set_key(key, iv);
        zk_prover.alloc(&mut prover, SENT_LEN).unwrap();

        let (key, iv) = keys(&mut verifier, KEY, IV, Role::Verifier);
        let mut auth_verifier = Authenticator::new(encoding.iter(), hashes.iter(), Some(&partial));
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

        proof.verify().unwrap();

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
    }

    #[rstest]
    #[tokio::test]
    async fn test_authenticator_recv(
        encoding: Vec<(Direction, RangeSet<usize>)>,
        hashes: Vec<(Direction, RangeSet<usize>, HashAlgId)>,
        decoding: (RangeSet<usize>, RangeSet<usize>),
        transcript: TlsTranscript,
        transcript_refs: TranscriptRefs,
    ) {
        let (sent_decdoding, recv_decdoding) = decoding;
        let partial = transcript
            .to_transcript()
            .unwrap()
            .to_partial(sent_decdoding, recv_decdoding);

        let (mut ctx_p, mut ctx_v) = test_st_context(8);

        let (mut prover, mut verifier) = vms();
        let mut refs_prover = transcript_refs.clone();
        let mut refs_verifier = transcript_refs;

        let (key, iv) = keys(&mut prover, KEY, IV, Role::Prover);
        let mut auth_prover = Authenticator::new(encoding.iter(), hashes.iter(), Some(&partial));
        let mut zk_prover = ZkAesCtr::new(Role::Prover);
        zk_prover.set_key(key, iv);
        zk_prover.alloc(&mut prover, RECV_LEN).unwrap();

        let (key, iv) = keys(&mut verifier, KEY, IV, Role::Verifier);
        let mut auth_verifier = Authenticator::new(encoding.iter(), hashes.iter(), Some(&partial));
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

        proof.verify().unwrap();

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
    }

    #[rstest]
    #[tokio::test]
    async fn test_authenticator_sent_verify_fail(
        encoding: Vec<(Direction, RangeSet<usize>)>,
        hashes: Vec<(Direction, RangeSet<usize>, HashAlgId)>,
        decoding: (RangeSet<usize>, RangeSet<usize>),
        transcript: TlsTranscript,
        transcript_refs: TranscriptRefs,
    ) {
        let (sent_decdoding, recv_decdoding) = decoding;
        let partial = transcript
            .to_transcript()
            .unwrap()
            .to_partial(sent_decdoding, recv_decdoding);

        let (mut ctx_p, mut ctx_v) = test_st_context(8);

        let (mut prover, mut verifier) = vms();
        let mut refs_prover = transcript_refs.clone();
        let mut refs_verifier = transcript_refs;

        let (key, iv) = keys(&mut prover, KEY, IV, Role::Prover);
        let mut auth_prover = Authenticator::new(encoding.iter(), hashes.iter(), Some(&partial));
        let mut zk_prover = ZkAesCtr::new(Role::Prover);
        zk_prover.set_key(key, iv);
        zk_prover.alloc(&mut prover, SENT_LEN).unwrap();

        let (key, iv) = keys(&mut verifier, KEY, IV, Role::Verifier);
        let mut auth_verifier = Authenticator::new(encoding.iter(), hashes.iter(), Some(&partial));
        let mut zk_verifier = ZkAesCtr::new(Role::Verifier);
        zk_verifier.set_key(key, iv);
        zk_verifier.alloc(&mut verifier, SENT_LEN).unwrap();

        let _ = auth_prover
            .auth_sent(&mut prover, &mut zk_prover, &transcript, &mut refs_prover)
            .unwrap();

        // Forge verifier transcript to check if verify fails.
        // Use an index which is part of the proving range.
        let forged = forged();

        let proof = auth_verifier
            .auth_sent(&mut verifier, &mut zk_verifier, &forged, &mut refs_verifier)
            .unwrap();

        tokio::try_join!(
            prover.execute_all(&mut ctx_p),
            verifier.execute_all(&mut ctx_v)
        )
        .unwrap();

        let err = proof.verify().unwrap_err();
        assert!(matches!(err.0, ErrorRepr::InvalidCiphertext));
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
    fn encoding() -> Vec<(Direction, RangeSet<usize>)> {
        let sent = 800..2000;
        let recv = 5000..5800;

        let encoding = vec![
            (Direction::Sent, sent.into()),
            (Direction::Received, recv.into()),
        ];
        encoding
    }

    #[fixture]
    fn hashes() -> Vec<(Direction, RangeSet<usize>, HashAlgId)> {
        let sent = 2600..3700;
        let recv = 6800..RECV_LEN;

        let alg = HashAlgId::SHA256;

        let hashes = vec![
            (Direction::Sent, sent.into(), alg),
            (Direction::Received, recv.into(), alg),
        ];
        hashes
    }

    fn vms() -> (Prover<IdealRCOTReceiver>, Verifier<IdealRCOTSender>) {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (ot_send, ot_recv) = ideal_rcot(rng.random(), delta.into_inner());

        let prover = Prover::new(ProverConfig::default(), ot_recv);
        let verifier = Verifier::new(VerifierConfig::default(), delta, ot_send);

        (prover, verifier)
    }

    #[fixture]
    fn transcript() -> TlsTranscript {
        let sent = LIBER_PRIMUS.as_bytes()[..SENT_LEN].to_vec();

        let mut recv = lipsum(RECV_LEN).into_bytes();
        recv.truncate(RECV_LEN);

        tlsn_core::fixtures::transcript::transcript_fixture(&sent, &recv)
    }

    #[fixture]
    fn forged() -> TlsTranscript {
        const WRONG_BYTE_INDEX: usize = 610;

        let mut sent = LIBER_PRIMUS.as_bytes()[..SENT_LEN].to_vec();
        sent[WRONG_BYTE_INDEX] = sent[WRONG_BYTE_INDEX].wrapping_add(1);

        let mut recv = lipsum(RECV_LEN).into_bytes();
        recv.truncate(RECV_LEN);

        tlsn_core::fixtures::transcript::transcript_fixture(&sent, &recv)
    }

    #[fixture]
    fn transcript_refs(transcript: TlsTranscript) -> TranscriptRefs {
        let sent_len = transcript
            .sent()
            .iter()
            .filter_map(|record| {
                if matches!(record.typ, ContentType::ApplicationData) {
                    Some(record.ciphertext.len())
                } else {
                    None
                }
            })
            .sum();
        let recv_len = transcript
            .recv()
            .iter()
            .filter_map(|record| {
                if matches!(record.typ, ContentType::ApplicationData) {
                    Some(record.ciphertext.len())
                } else {
                    None
                }
            })
            .sum();

        TranscriptRefs::new(sent_len, recv_len)
    }

    const SENT_LEN: usize = 4096;
    const RECV_LEN: usize = 8192;
}
