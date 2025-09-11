//! Selective disclosure.

use crate::commit::TranscriptRefs;
use mpz_memory_core::{
    Array, MemoryExt,
    binary::{Binary, U8},
};
use mpz_vm_core::Vm;
use rangeset::{Intersection, RangeSet, Subset, Union};
use tlsn_core::transcript::{ContentType, Direction, PartialTranscript, TlsTranscript};

/// Decodes parts of the transcript.
///
/// # Arguments
///
/// * `vm` - The virtual machine.
/// * `key` - The server write key.
/// * `iv` - The server write iv.
/// * `decoding_ranges` - The decoding ranges.
/// * `transcript_refs` - The transcript references.
pub(crate) fn decode_transcript(
    vm: &mut dyn Vm<Binary>,
    key: Array<U8, 16>,
    iv: Array<U8, 4>,
    decoding_ranges: (&RangeSet<usize>, &RangeSet<usize>),
    transcript_refs: &mut TranscriptRefs,
) -> Result<(), DecodeError> {
    let (sent, recv) = decoding_ranges;

    let sent_refs = transcript_refs.get(Direction::Sent, sent);
    for slice in sent_refs.into_iter() {
        // Drop the future, we don't need it.
        drop(vm.decode(slice).map_err(DecodeError::vm));
    }

    transcript_refs.mark_decoded(Direction::Sent, sent);

    // If possible use server write key for decoding.
    let fully_decoded = recv.union(&transcript_refs.decoded(Direction::Received));
    let full_range = 0..transcript_refs.max_len(Direction::Received);

    if fully_decoded == full_range {
        // Drop the future, we don't need it.
        drop(vm.decode(key).map_err(DecodeError::vm)?);
        drop(vm.decode(iv).map_err(DecodeError::vm)?);

        transcript_refs.mark_decoded(Direction::Received, &full_range.into());
    } else {
        let recv_refs = transcript_refs.get(Direction::Received, recv);
        for slice in recv_refs {
            // Drop the future, we don't need it.
            drop(vm.decode(slice).map_err(DecodeError::vm));
        }

        transcript_refs.mark_decoded(Direction::Received, recv);
    }

    Ok(())
}

/// Verifies parts of the transcript.
///
/// # Arguments
///
/// * `vm` - The virtual machine.
/// * `key` - The server write key.
/// * `iv` - The server write iv.
/// * `decoding_ranges` - The decoding ranges.
/// * `partial` - The partial transcript.
/// * `transcript_refs` - The transcript references.
/// * `transcript` - The TLS transcript.
pub(crate) fn verify_transcript(
    vm: &mut dyn Vm<Binary>,
    key: Array<U8, 16>,
    iv: Array<U8, 4>,
    decoding_ranges: (&RangeSet<usize>, &RangeSet<usize>),
    partial: Option<&PartialTranscript>,
    transcript_refs: &mut TranscriptRefs,
    transcript: &TlsTranscript,
) -> Result<(), DecodeError> {
    let Some(partial) = partial else {
        return Err(DecodeError(ErrorRepr::MissingPartialTranscript));
    };
    let (sent, recv) = decoding_ranges;
    let mut authenticated_data = Vec::new();

    // Add sent transcript parts.
    let sent_refs = transcript_refs.get(Direction::Sent, sent);
    for data in sent_refs.into_iter() {
        let plaintext = vm
            .get(data)
            .map_err(DecodeError::vm)?
            .ok_or(DecodeError(ErrorRepr::MissingPlaintext))?;
        authenticated_data.extend_from_slice(&plaintext);
    }

    // Add received transcript parts, if possible using key and iv.
    if let (Some(key), Some(iv)) = (
        vm.get(key).map_err(DecodeError::vm)?,
        vm.get(iv).map_err(DecodeError::vm)?,
    ) {
        let plaintext = verify_with_keys(key, iv, recv, transcript)?;
        authenticated_data.extend_from_slice(&plaintext);
    } else {
        let recv_refs = transcript_refs.get(Direction::Received, recv);
        for data in recv_refs {
            let plaintext = vm
                .get(data)
                .map_err(DecodeError::vm)?
                .ok_or(DecodeError(ErrorRepr::MissingPlaintext))?;
            authenticated_data.extend_from_slice(&plaintext);
        }
    }

    let mut purported_data = Vec::with_capacity(authenticated_data.len());

    for range in sent.iter_ranges() {
        purported_data.extend_from_slice(&partial.sent_unsafe()[range]);
    }
    for range in recv.iter_ranges() {
        purported_data.extend_from_slice(&partial.received_unsafe()[range]);
    }

    if purported_data != authenticated_data {
        return Err(DecodeError(ErrorRepr::InconsistentTranscript));
    }

    Ok(())
}

/// Checks the transcript length.
///
/// # Arguments
///
/// * `partial` - The partial transcript.
/// * `transcript` - The TLS transcript.
pub(crate) fn check_transcript_length(
    partial: Option<&PartialTranscript>,
    transcript: &TlsTranscript,
) -> Result<(), DecodeError> {
    let Some(partial) = partial else {
        return Err(DecodeError(ErrorRepr::MissingPartialTranscript));
    };

    let sent_len: usize = transcript
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
    let recv_len: usize = transcript
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

    // Check ranges.
    if partial.len_sent() != sent_len || partial.len_received() != recv_len {
        return Err(DecodeError(ErrorRepr::VerifyTranscriptLength));
    }

    Ok(())
}

fn verify_with_keys(
    key: [u8; 16],
    iv: [u8; 4],
    decoding_ranges: &RangeSet<usize>,
    transcript: &TlsTranscript,
) -> Result<Vec<u8>, DecodeError> {
    let mut plaintexts = Vec::with_capacity(decoding_ranges.len());
    let mut position = 0_usize;

    let recv_data = transcript
        .recv()
        .iter()
        .filter(|record| record.typ == ContentType::ApplicationData);

    for record in recv_data {
        let current = position..position + record.ciphertext.len();

        if !current.is_subset(decoding_ranges) {
            position += record.ciphertext.len();
            continue;
        }

        let nonce = record
            .explicit_nonce
            .clone()
            .try_into()
            .expect("explicit nonce should be 8 bytes");
        let plaintext = aes_apply_keystream(key, iv, nonce, &record.ciphertext);

        let record_decoding_range = decoding_ranges.intersection(&current);
        for r in record_decoding_range.iter_ranges() {
            let shifted = r.start - position..r.end - position;
            plaintexts.extend_from_slice(&plaintext[shifted]);
        }

        position += record.ciphertext.len()
    }
    Ok(plaintexts)
}

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

/// A decoding error.
#[derive(Debug, thiserror::Error)]
#[error("decode error: {0}")]
pub(crate) struct DecodeError(#[source] ErrorRepr);

impl DecodeError {
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
    #[error("missing partial transcript")]
    MissingPartialTranscript,
    #[error("length of partial transcript does not match expected length")]
    VerifyTranscriptLength,
    #[error("provided transcript does not match exptected")]
    InconsistentTranscript,
    #[error("trying to get plaintext, but it is missing")]
    MissingPlaintext,
}

#[cfg(test)]
mod tests {
    use crate::{
        Role,
        commit::{
            TranscriptRefs,
            decode::{DecodeError, ErrorRepr, decode_transcript, verify_transcript},
        },
    };
    use mpz_common::context::test_st_context;
    use mpz_garble_core::Delta;
    use mpz_memory_core::{
        Array, MemoryExt, Vector, ViewExt,
        binary::{Binary, U8},
    };
    use mpz_ot::ideal::rcot::{IdealRCOTReceiver, IdealRCOTSender, ideal_rcot};
    use mpz_vm_core::{Execute, Vm};
    use mpz_zk::{Prover, ProverConfig, Verifier, VerifierConfig};
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use rangeset::{RangeSet, UnionMut};
    use rstest::{fixture, rstest};
    use tlsn_core::{
        fixtures::transcript::{IV, KEY, forged_transcript, transcript_fixture},
        transcript::{Direction, Idx, PartialTranscript, TlsTranscript},
    };

    #[rstest]
    #[tokio::test]
    async fn test_decode(
        decoding: (RangeSet<usize>, RangeSet<usize>),
        transcript: TlsTranscript,
        transcript_refs: TranscriptRefs,
    ) {
        let partial = partial(&transcript, decoding.clone());
        decode(decoding, partial, transcript, transcript_refs)
            .await
            .unwrap();
    }

    #[rstest]
    #[tokio::test]
    async fn test_decode_fail(
        decoding: (RangeSet<usize>, RangeSet<usize>),
        forged: TlsTranscript,
        transcript: TlsTranscript,
        transcript_refs: TranscriptRefs,
    ) {
        let partial = partial(&forged, decoding.clone());
        let err = decode(decoding, partial, transcript, transcript_refs)
            .await
            .unwrap_err();

        assert!(matches!(err.0, ErrorRepr::InconsistentTranscript));
    }

    #[rstest]
    #[tokio::test]
    async fn test_decode_all(
        decoding_full: (RangeSet<usize>, RangeSet<usize>),
        transcript: TlsTranscript,
        transcript_refs: TranscriptRefs,
    ) {
        let partial = partial(&transcript, decoding_full.clone());
        decode(decoding_full, partial, transcript, transcript_refs)
            .await
            .unwrap();
    }

    #[rstest]
    #[tokio::test]
    async fn test_decode_all_fail(
        decoding_full: (RangeSet<usize>, RangeSet<usize>),
        forged: TlsTranscript,
        transcript: TlsTranscript,
        transcript_refs: TranscriptRefs,
    ) {
        let partial = partial(&forged, decoding_full.clone());
        let err = decode(decoding_full, partial, transcript, transcript_refs)
            .await
            .unwrap_err();

        assert!(matches!(err.0, ErrorRepr::InconsistentTranscript));
    }

    async fn decode(
        decoding: (RangeSet<usize>, RangeSet<usize>),
        partial: PartialTranscript,
        transcript: TlsTranscript,
        transcript_refs: TranscriptRefs,
    ) -> Result<(), DecodeError> {
        let (sent, recv) = decoding;

        let (mut ctx_p, mut ctx_v) = test_st_context(8);
        let (mut prover, mut verifier) = vms();

        let mut transcript_refs_verifier = transcript_refs.clone();
        let mut transcript_refs_prover = transcript_refs;

        let key: [u8; 16] = KEY;
        let iv: [u8; 4] = IV;

        let (key_prover, iv_prover) = assign_keys(&mut prover, key, iv, Role::Prover);
        let (key_verifier, iv_verifier) = assign_keys(&mut verifier, key, iv, Role::Verifier);

        assign_transcript(
            &mut prover,
            Role::Prover,
            &transcript,
            &mut transcript_refs_prover,
        );
        assign_transcript(
            &mut verifier,
            Role::Verifier,
            &transcript,
            &mut transcript_refs_verifier,
        );

        decode_transcript(
            &mut prover,
            key_prover,
            iv_prover,
            (&sent, &recv),
            &mut transcript_refs_prover,
        )
        .unwrap();

        decode_transcript(
            &mut verifier,
            key_verifier,
            iv_verifier,
            (&sent, &recv),
            &mut transcript_refs_verifier,
        )
        .unwrap();

        tokio::try_join!(
            prover.execute_all(&mut ctx_p),
            verifier.execute_all(&mut ctx_v),
        )
        .unwrap();

        verify_transcript(
            &mut verifier,
            key_verifier,
            iv_verifier,
            (&sent, &recv),
            Some(&partial),
            &mut transcript_refs_verifier,
            &transcript,
        )
    }

    fn assign_keys(
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

    fn assign_transcript(
        vm: &mut dyn Vm<Binary>,
        role: Role,
        transcript: &TlsTranscript,
        transcript_refs: &mut TranscriptRefs,
    ) {
        let mut pos = 0_usize;
        for record in transcript.iter_sent_app_data() {
            let len = record.ciphertext.len();

            let cipher_ref: Vector<U8> = vm.alloc_vec(len).unwrap();
            vm.mark_public(cipher_ref).unwrap();
            vm.assign(cipher_ref, record.ciphertext.clone()).unwrap();
            vm.commit(cipher_ref).unwrap();

            let plaintext_ref: Vector<U8> = vm.alloc_vec(len).unwrap();
            if let Role::Prover = role {
                vm.mark_private(plaintext_ref).unwrap();
                vm.assign(plaintext_ref, record.plaintext.clone().unwrap())
                    .unwrap();
            } else {
                vm.mark_blind(plaintext_ref).unwrap();
            }
            vm.commit(plaintext_ref).unwrap();

            let index = pos..pos + record.ciphertext.len();
            transcript_refs.add(Direction::Sent, &index, plaintext_ref);

            pos += record.ciphertext.len();
        }

        pos = 0;
        for record in transcript.iter_recv_app_data() {
            let len = record.ciphertext.len();

            let cipher_ref: Vector<U8> = vm.alloc_vec(len).unwrap();
            vm.mark_public(cipher_ref).unwrap();
            vm.assign(cipher_ref, record.ciphertext.clone()).unwrap();
            vm.commit(cipher_ref).unwrap();

            let plaintext_ref: Vector<U8> = vm.alloc_vec(len).unwrap();
            if let Role::Prover = role {
                vm.mark_private(plaintext_ref).unwrap();
                vm.assign(plaintext_ref, record.plaintext.clone().unwrap())
                    .unwrap();
            } else {
                vm.mark_blind(plaintext_ref).unwrap();
            }
            vm.commit(plaintext_ref).unwrap();

            let index = pos..pos + record.ciphertext.len();
            transcript_refs.add(Direction::Received, &index, plaintext_ref);

            pos += record.ciphertext.len();
        }
    }

    fn partial(
        transcript: &TlsTranscript,
        decoding: (RangeSet<usize>, RangeSet<usize>),
    ) -> PartialTranscript {
        let (sent, recv) = decoding;

        transcript
            .to_transcript()
            .unwrap()
            .to_partial(Idx::new(sent), Idx::new(recv))
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
    fn decoding_full(transcript: TlsTranscript) -> (RangeSet<usize>, RangeSet<usize>) {
        let transcript = transcript.to_transcript().unwrap();
        let (len_sent, len_recv) = transcript.len();

        let sent = (0..len_sent).into();
        let recv = (0..len_recv).into();

        (sent, recv)
    }

    #[fixture]
    fn transcript() -> TlsTranscript {
        transcript_fixture()
    }

    #[fixture]
    fn forged() -> TlsTranscript {
        forged_transcript(Direction::Received, 2200)
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

    fn vms() -> (Prover<IdealRCOTReceiver>, Verifier<IdealRCOTSender>) {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (ot_send, ot_recv) = ideal_rcot(rng.random(), delta.into_inner());

        let prover = Prover::new(ProverConfig::default(), ot_recv);
        let verifier = Verifier::new(VerifierConfig::default(), delta, ot_send);

        (prover, verifier)
    }
}
