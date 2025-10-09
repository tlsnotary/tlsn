use mpc_tls::SessionKeys;
use mpz_common::Context;
use mpz_memory_core::binary::Binary;
use mpz_vm_core::Vm;
use rangeset::{RangeSet, UnionMut};
use serio::SinkExt;
use tlsn_core::{
    ProveConfig, ProveRequest, ProverOutput,
    connection::{HandshakeData, ServerName},
    transcript::{
        ContentType, Direction, TlsTranscript, Transcript, TranscriptCommitment, TranscriptSecret,
    },
};

use crate::{
    commit::{auth::prove_plaintext, hash::prove_hash, transcript::TranscriptRefs},
    encoding::{self, MacStore},
    prover::ProverError,
    zk_aes_ctr::ZkAesCtr,
};

pub(crate) async fn prove<T: Vm<Binary> + MacStore + Send + Sync>(
    ctx: &mut Context,
    vm: &mut T,
    keys: &SessionKeys,
    server_name: &ServerName,
    transcript: &Transcript,
    tls_transcript: &TlsTranscript,
    config: &ProveConfig,
) -> Result<ProverOutput, ProverError> {
    let mut output = ProverOutput {
        transcript_commitments: Vec::default(),
        transcript_secrets: Vec::default(),
    };

    let request = ProveRequest {
        handshake: config.server_identity().then(|| {
            (
                server_name.clone(),
                HandshakeData {
                    certs: tls_transcript
                        .server_cert_chain()
                        .expect("server cert chain is present")
                        .to_vec(),
                    sig: tls_transcript
                        .server_signature()
                        .expect("server signature is present")
                        .clone(),
                    binding: tls_transcript.certificate_binding().clone(),
                },
            )
        }),
        transcript: config
            .reveal()
            .map(|(sent, recv)| transcript.to_partial(sent.clone(), recv.clone())),
        transcript_commit: config.transcript_commit().map(|config| config.to_request()),
    };

    ctx.io_mut()
        .send(request)
        .await
        .map_err(ProverError::from)?;

    let mut auth_sent_ranges = RangeSet::default();
    let mut auth_recv_ranges = RangeSet::default();

    let (reveal_sent, reveal_recv) = config.reveal().cloned().unwrap_or_default();

    auth_sent_ranges.union_mut(&reveal_sent);
    auth_recv_ranges.union_mut(&reveal_recv);

    if let Some(commit_config) = config.transcript_commit() {
        commit_config
            .iter_hash()
            .for_each(|((direction, idx), _)| match direction {
                Direction::Sent => auth_sent_ranges.union_mut(idx),
                Direction::Received => auth_recv_ranges.union_mut(idx),
            });

        commit_config
            .iter_encoding()
            .for_each(|(direction, idx)| match direction {
                Direction::Sent => auth_sent_ranges.union_mut(idx),
                Direction::Received => auth_recv_ranges.union_mut(idx),
            });
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

    let sent_refs = prove_plaintext(
        vm,
        &mut zk_aes_sent,
        transcript.sent(),
        &auth_sent_ranges,
        &reveal_sent,
    )
    .map_err(ProverError::commit)?;
    let recv_refs = prove_plaintext(
        vm,
        &mut zk_aes_recv,
        transcript.received(),
        &auth_recv_ranges,
        &reveal_recv,
    )
    .map_err(ProverError::commit)?;

    let transcript_refs = TranscriptRefs {
        sent: sent_refs,
        recv: recv_refs,
    };

    let hash_commitments = if let Some(commit_config) = config.transcript_commit()
        && commit_config.has_hash()
    {
        Some(
            prove_hash(
                vm,
                &transcript_refs,
                commit_config
                    .iter_hash()
                    .map(|((dir, idx), alg)| (*dir, idx.clone(), *alg)),
            )
            .map_err(ProverError::commit)?,
        )
    } else {
        None
    };

    vm.execute_all(ctx).await.map_err(ProverError::zk)?;

    if let Some(commit_config) = config.transcript_commit()
        && commit_config.has_encoding()
    {
        let mut sent_ranges = RangeSet::default();
        let mut recv_ranges = RangeSet::default();
        for (dir, idx) in commit_config.iter_encoding() {
            match dir {
                Direction::Sent => sent_ranges.union_mut(idx),
                Direction::Received => recv_ranges.union_mut(idx),
            }
        }

        let sent_map = transcript_refs
            .sent
            .index(&sent_ranges)
            .expect("indices are valid");
        let recv_map = transcript_refs
            .recv
            .index(&recv_ranges)
            .expect("indices are valid");

        let (commitment, tree) = encoding::receive(
            ctx,
            vm,
            *commit_config.encoding_hash_alg(),
            &sent_map,
            &recv_map,
            commit_config.iter_encoding(),
        )
        .await?;

        output
            .transcript_commitments
            .push(TranscriptCommitment::Encoding(commitment));
        output
            .transcript_secrets
            .push(TranscriptSecret::Encoding(tree));
    }

    if let Some((hash_fut, hash_secrets)) = hash_commitments {
        let hash_commitments = hash_fut.try_recv().map_err(ProverError::commit)?;
        for (commitment, secret) in hash_commitments.into_iter().zip(hash_secrets) {
            output
                .transcript_commitments
                .push(TranscriptCommitment::Hash(commitment));
            output
                .transcript_secrets
                .push(TranscriptSecret::Hash(secret));
        }
    }

    Ok(output)
}
