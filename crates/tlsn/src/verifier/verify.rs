use mpc_tls::SessionKeys;
use mpz_common::Context;
use mpz_memory_core::binary::Binary;
use mpz_predicate::Pred;
use mpz_vm_core::Vm;
use rangeset::set::RangeSet;
use tlsn_core::{
    VerifierOutput,
    config::prove::ProveRequest,
    connection::{HandshakeData, ServerName},
    transcript::{
        ContentType, Direction, PartialTranscript, Record, TlsTranscript, TranscriptCommitment,
    },
    webpki::ServerCertVerifier,
};

use crate::{
    transcript_internal::{
        TranscriptRefs,
        auth::verify_plaintext,
        commit::{
            encoding::{self, KeyStore},
            hash::verify_hash,
        },
        predicate::verify_predicates,
    },
    verifier::VerifierError,
};

/// A function that resolves predicate names to predicates.
///
/// The verifier must provide this to look up predicates by name,
/// based on out-of-band agreement with the prover.
///
/// The function receives:
/// - The predicate name
/// - The byte indices the predicate operates on (from the prover's request)
///
/// The verifier should validate that the indices make sense for the predicate
/// and return the appropriate predicate built with those indices.
pub type PredicateResolver = dyn Fn(&str, &RangeSet<usize>) -> Option<Pred> + Send + Sync;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn verify<T: Vm<Binary> + KeyStore + Send + Sync>(
    ctx: &mut Context,
    vm: &mut T,
    keys: &SessionKeys,
    cert_verifier: &ServerCertVerifier,
    tls_transcript: &TlsTranscript,
    request: ProveRequest,
    handshake: Option<(ServerName, HandshakeData)>,
    transcript: Option<PartialTranscript>,
    predicate_resolver: Option<&PredicateResolver>,
) -> Result<VerifierOutput, VerifierError> {
    let ciphertext_sent = collect_ciphertext(tls_transcript.sent());
    let ciphertext_recv = collect_ciphertext(tls_transcript.recv());

    let transcript = if let Some((auth_sent, auth_recv)) = request.reveal() {
        let Some(transcript) = transcript else {
            return Err(VerifierError::verify(
                "prover requested to reveal data but did not send transcript",
            ));
        };

        if transcript.len_sent() != ciphertext_sent.len()
            || transcript.len_received() != ciphertext_recv.len()
        {
            return Err(VerifierError::verify(
                "prover sent transcript with incorrect length",
            ));
        }

        if transcript.sent_authed() != auth_sent {
            return Err(VerifierError::verify(
                "prover sent transcript with incorrect sent authed data",
            ));
        }

        if transcript.received_authed() != auth_recv {
            return Err(VerifierError::verify(
                "prover sent transcript with incorrect received authed data",
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

    let (mut commit_sent, mut commit_recv) = (RangeSet::default(), RangeSet::default());
    if let Some(commit_config) = request.transcript_commit() {
        commit_config
            .iter_hash()
            .for_each(|(direction, idx, _)| match direction {
                Direction::Sent => commit_sent.union_mut(idx),
                Direction::Received => commit_recv.union_mut(idx),
            });

        if let Some((sent, recv)) = commit_config.encoding() {
            commit_sent.union_mut(sent);
            commit_recv.union_mut(recv);
        }
    }

    // Build predicate ranges from request
    let (mut predicate_sent, mut predicate_recv) = (RangeSet::default(), RangeSet::default());
    for predicate_req in request.predicates() {
        match predicate_req.direction() {
            Direction::Sent => predicate_sent.union_mut(predicate_req.indices()),
            Direction::Received => predicate_recv.union_mut(predicate_req.indices()),
        }
    }

    let (sent_refs, sent_proof) = verify_plaintext(
        vm,
        keys.client_write_key,
        keys.client_write_iv,
        transcript.sent_unsafe(),
        &ciphertext_sent,
        tls_transcript
            .sent()
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData),
        transcript.sent_authed(),
        &commit_sent,
        &predicate_sent,
    )
    .map_err(VerifierError::zk)?;
    let (recv_refs, recv_proof) = verify_plaintext(
        vm,
        keys.server_write_key,
        keys.server_write_iv,
        transcript.received_unsafe(),
        &ciphertext_recv,
        tls_transcript
            .recv()
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData),
        transcript.received_authed(),
        &commit_recv,
        &predicate_recv,
    )
    .map_err(VerifierError::zk)?;

    let transcript_refs = TranscriptRefs {
        sent: sent_refs,
        recv: recv_refs,
    };

    let mut transcript_commitments = Vec::new();
    let mut hash_commitments = None;
    if let Some(commit_config) = request.transcript_commit()
        && commit_config.has_hash()
    {
        hash_commitments = Some(
            verify_hash(vm, &transcript_refs, commit_config.iter_hash().cloned())
                .map_err(VerifierError::verify)?,
        );
    }

    // Verify predicates if any were requested
    let predicate_proof = if !request.predicates().is_empty() {
        let resolver = predicate_resolver.ok_or_else(|| {
            VerifierError::predicate("predicates requested but no resolver provided")
        })?;

        let predicates = request
            .predicates()
            .iter()
            .map(|req| {
                let predicate = resolver(req.name(), req.indices()).ok_or_else(|| {
                    VerifierError::predicate(format!("unknown predicate: {}", req.name()))
                })?;
                Ok((req.direction(), req.indices().clone(), predicate))
            })
            .collect::<Result<Vec<_>, VerifierError>>()?;

        Some(verify_predicates(vm, &transcript_refs, predicates).map_err(VerifierError::predicate)?)
    } else {
        None
    };

    vm.execute_all(ctx).await.map_err(VerifierError::zk)?;

    sent_proof.verify().map_err(VerifierError::verify)?;
    recv_proof.verify().map_err(VerifierError::verify)?;

    // Verify predicate outputs after ZK execution
    if let Some(proof) = predicate_proof {
        proof.verify().map_err(VerifierError::predicate)?;
    }

    let mut encoder_secret = None;
    if let Some(commit_config) = request.transcript_commit()
        && let Some((sent, recv)) = commit_config.encoding()
    {
        let sent_map = transcript_refs
            .sent
            .index(sent)
            .expect("ranges were authenticated");
        let recv_map = transcript_refs
            .recv
            .index(recv)
            .expect("ranges were authenticated");

        let (secret, commitment) = encoding::transfer(ctx, vm, &sent_map, &recv_map).await?;
        encoder_secret = Some(secret);
        transcript_commitments.push(TranscriptCommitment::Encoding(commitment));
    }

    if let Some(hash_commitments) = hash_commitments {
        for commitment in hash_commitments.try_recv().map_err(VerifierError::verify)? {
            transcript_commitments.push(TranscriptCommitment::Hash(commitment));
        }
    }

    Ok(VerifierOutput {
        server_name,
        transcript: request.reveal().is_some().then_some(transcript),
        encoder_secret,
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
