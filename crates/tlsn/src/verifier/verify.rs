use mpc_tls::SessionKeys;
use mpz_common::Context;
use mpz_memory_core::binary::Binary;
use mpz_vm_core::Vm;
use rangeset::{RangeSet, UnionMut};
use tlsn_core::{
    ProveRequest, VerifierOutput,
    transcript::{
        ContentType, Direction, PartialTranscript, Record, TlsTranscript, TranscriptCommitment,
    },
    webpki::ServerCertVerifier,
};

use crate::{
    commit::{auth::verify_plaintext, hash::verify_hash, transcript::TranscriptRefs},
    encoding::{self, KeyStore},
    verifier::VerifierError,
    zk_aes_ctr::ZkAesCtr,
};

pub(crate) async fn verify<T: Vm<Binary> + KeyStore + Send + Sync>(
    ctx: &mut Context,
    vm: &mut T,
    keys: &SessionKeys,
    cert_verifier: &ServerCertVerifier,
    tls_transcript: &TlsTranscript,
    request: ProveRequest,
) -> Result<VerifierOutput, VerifierError> {
    let ProveRequest {
        handshake,
        transcript,
        transcript_commit,
    } = request;

    let ciphertext_sent = collect_ciphertext(tls_transcript.sent());
    let ciphertext_recv = collect_ciphertext(tls_transcript.recv());

    let has_reveal = transcript.is_some();
    let transcript = if let Some(transcript) = transcript {
        if transcript.len_sent() != ciphertext_sent.len()
            || transcript.len_received() != ciphertext_recv.len()
        {
            return Err(VerifierError::verify(
                "prover sent transcript with incorrect length",
            ));
        }

        transcript
    } else {
        PartialTranscript::new(ciphertext_sent.len(), ciphertext_recv.len())
    };

    let server_name = if let Some((name, cert_data)) = handshake {
        cert_data
            .verify(
                cert_verifier,
                tls_transcript.time(),
                tls_transcript.server_ephemeral_key(),
                &name,
            )
            .map_err(VerifierError::verify)?;

        Some(name)
    } else {
        None
    };

    let mut auth_sent_ranges = RangeSet::default();
    let mut auth_recv_ranges = RangeSet::default();

    auth_sent_ranges.union_mut(transcript.sent_authed());
    auth_recv_ranges.union_mut(transcript.received_authed());

    if let Some(commit_config) = transcript_commit.as_ref() {
        commit_config
            .iter_hash()
            .for_each(|(direction, idx, _)| match direction {
                Direction::Sent => auth_sent_ranges.union_mut(idx),
                Direction::Received => auth_recv_ranges.union_mut(idx),
            });

        if let Some((sent, recv)) = commit_config.encoding() {
            auth_sent_ranges.union_mut(sent);
            auth_recv_ranges.union_mut(recv);
        }
    }

    let mut zk_aes_sent = ZkAesCtr::new(
        keys.client_write_key,
        keys.client_write_iv,
        tls_transcript
            .sent()
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData),
    );
    let mut zk_aes_recv = ZkAesCtr::new(
        keys.server_write_key,
        keys.server_write_iv,
        tls_transcript
            .recv()
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData),
    );

    let (sent_refs, sent_proof) = verify_plaintext(
        vm,
        &mut zk_aes_sent,
        transcript.sent_unsafe(),
        &ciphertext_sent,
        &auth_sent_ranges,
        transcript.sent_authed(),
    )
    .map_err(VerifierError::zk)?;
    let (recv_refs, recv_proof) = verify_plaintext(
        vm,
        &mut zk_aes_recv,
        transcript.received_unsafe(),
        &ciphertext_recv,
        &auth_recv_ranges,
        transcript.received_authed(),
    )
    .map_err(VerifierError::zk)?;

    let transcript_refs = TranscriptRefs {
        sent: sent_refs,
        recv: recv_refs,
    };

    let mut transcript_commitments = Vec::new();
    let mut hash_commitments = None;
    if let Some(commit_config) = transcript_commit.as_ref()
        && commit_config.has_hash() {
            hash_commitments = Some(
                verify_hash(vm, &transcript_refs, commit_config.iter_hash().cloned())
                    .map_err(VerifierError::verify)?,
            );
        }

    vm.execute_all(ctx).await.map_err(VerifierError::zk)?;

    sent_proof.verify().map_err(VerifierError::verify)?;
    recv_proof.verify().map_err(VerifierError::verify)?;

    if let Some(commit_config) = transcript_commit
        && let Some((sent, recv)) = commit_config.encoding() {
            let sent_map = transcript_refs
                .sent
                .index(sent)
                .expect("ranges were authenticated");
            let recv_map = transcript_refs
                .recv
                .index(recv)
                .expect("ranges were authenticated");

            let commitment = encoding::transfer(ctx, vm, &sent_map, &recv_map).await?;
            transcript_commitments.push(TranscriptCommitment::Encoding(commitment));
        }

    if let Some(hash_commitments) = hash_commitments {
        for commitment in hash_commitments.try_recv().map_err(VerifierError::verify)? {
            transcript_commitments.push(TranscriptCommitment::Hash(commitment));
        }
    }

    Ok(VerifierOutput {
        server_name,
        transcript: has_reveal.then_some(transcript),
        transcript_commitments,
    })
}

fn collect_ciphertext<'a>(records: impl IntoIterator<Item = &'a Record>) -> Vec<u8> {
    let mut ciphertext = Vec::new();
    records
        .into_iter()
        .filter(|record| record.typ == ContentType::ApplicationData)
        .for_each(|record| {
            ciphertext.extend_from_slice(&record.ciphertext);
        });
    ciphertext
}
