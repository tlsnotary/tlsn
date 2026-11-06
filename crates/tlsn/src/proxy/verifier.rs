use crate::{
    Error as TlsnError, TlsOutput,
    deps::VerifierZk,
    msg::ProxyFinished,
    proxy::{MsVisibility, References, VerifyDataCheck, alloc_proxy_refs},
};
use hmac_sha256::Prf;
use mpz_common::Context;
use mpz_memory_core::MemoryExt;
use mpz_vm_core::Execute;
use serio::stream::IoStreamExt;
use tlsn_core::transcript::TlsTranscript;

pub(crate) struct ProxyVerifier {
    ctx: Context,
    vm: VerifierZk,
    prf: Prf,
    refs: Option<References>,
    cf_vd_check: VerifyDataCheck,
    sf_vd_check: VerifyDataCheck,
}

impl ProxyVerifier {
    pub(crate) fn new(prf: Prf, vm: VerifierZk, ctx: Context) -> Self {
        Self {
            ctx,
            vm,
            prf,
            refs: None,
            cf_vd_check: VerifyDataCheck::default(),
            sf_vd_check: VerifyDataCheck::default(),
        }
    }

    pub(crate) fn alloc(&mut self) -> Result<(), TlsnError> {
        self.refs = Some(alloc_proxy_refs(
            &mut self.vm,
            &mut self.prf,
            &mut self.cf_vd_check,
            &mut self.sf_vd_check,
            MsVisibility::Blind,
        )?);
        Ok(())
    }

    pub(crate) async fn preprocess(&mut self) -> Result<(), TlsnError> {
        self.vm.flush(&mut self.ctx).await.map_err(|e| {
            TlsnError::internal()
                .with_msg("preprocessing proxy-tls failed")
                .with_source(e)
        })
    }

    /// Waits for the prover to signal that it is done with the proxy
    /// connection.
    pub(crate) async fn wait_finished(&mut self) -> Result<ProxyFinished, TlsnError> {
        self.ctx
            .io_mut()
            .expect_next::<ProxyFinished>()
            .await
            .map_err(|e| {
                TlsnError::io()
                    .with_msg("failed to receive proxy finished message")
                    .with_source(e)
            })
    }

    pub(crate) async fn finalize(
        mut self,
        sent: &[u8],
        recv: &[u8],
        conn_time: u64,
        finished: &ProxyFinished,
    ) -> Result<
        (
            Context,
            VerifierZk,
            TlsOutput,
            VerifyDataCheck,
            VerifyDataCheck,
        ),
        TlsnError,
    > {
        // With ProxyFinished gated on both directions finishing, the two sides
        // must agree on the byte counts.
        ensure_equal(sent, finished.tls_sent, "sent")?;
        ensure_equal(recv, finished.tls_recv, "recv")?;

        let tls_transcript = TlsTranscript::builder()
            .time(conn_time)
            .tls_sent(sent)
            .tls_recv(recv)
            .build()
            .map_err(|e| {
                TlsnError::internal()
                    .with_msg("verifier could not build tls transcript")
                    .with_source(e)
            })?;
        tracing::debug!("successfully parsed transcript");

        let mut refs = self
            .refs
            .ok_or_else(|| TlsnError::internal().with_msg("proxy verifier key refs are missing"))?;

        let cf_hash: [u8; 32] = tls_transcript.cf_hash().ok_or_else(|| {
            TlsnError::internal().with_msg("client finished hash is missing from tls transcript")
        })?;

        let tlsn_core::connection::CertBinding::V1_2(binding) =
            tls_transcript.certificate_binding()
        else {
            return Err(
                TlsnError::internal().with_msg("version of certificate binding is not supported")
            );
        };

        tracing::debug!("computing PRF...");
        self.vm
            .commit(refs.ms)
            .map_err(|e| TlsnError::internal().with_source(e))?;

        self.prf.set_client_random(binding.client_random);
        self.prf
            .set_server_random(binding.server_random)
            .map_err(|e| TlsnError::internal().with_source(e))?;
        self.prf
            .set_cf_hash(cf_hash)
            .map_err(|e| TlsnError::internal().with_source(e))?;

        // First flush: master_secret, key_expansion, and client_finished
        // progress. server_finished sits idle (sf_hash not yet set).
        while self.prf.wants_flush() {
            self.prf
                .flush(&mut self.vm)
                .map_err(|e| TlsnError::internal().with_source(e))?;
            self.vm
                .execute_all(&mut self.ctx)
                .await
                .map_err(|e| TlsnError::internal().with_source(e))?;
        }

        tracing::debug!("decoding client finished verify data...");
        let cf_vd = refs
            .cf_vd
            .try_recv()
            .map_err(|e| TlsnError::internal().with_source(e))?
            .ok_or(TlsnError::internal().with_msg("unable to receive cf_vd from decoding"))?;

        // Now that cf_vd is known, compute sf_hash and resume the PRF.
        let sf_hash: [u8; 32] = tls_transcript.sf_hash(&cf_vd).ok_or_else(|| {
            TlsnError::internal().with_msg("server finished hash is missing from tls transcript")
        })?;

        self.prf
            .set_sf_hash(sf_hash)
            .map_err(|e| TlsnError::internal().with_source(e))?;

        // Second flush: server_finished completes.
        while self.prf.wants_flush() {
            self.prf
                .flush(&mut self.vm)
                .map_err(|e| TlsnError::internal().with_source(e))?;
            self.vm
                .execute_all(&mut self.ctx)
                .await
                .map_err(|e| TlsnError::internal().with_source(e))?;
        }

        tracing::debug!("decoding server finished verify data...");

        let cf_record = tls_transcript.client_finished();
        self.cf_vd_check.assign(
            &mut self.vm,
            &cf_record.explicit_nonce,
            &cf_record.ciphertext,
        )?;

        let sf_record = tls_transcript.server_finished();
        self.sf_vd_check.assign(
            &mut self.vm,
            &sf_record.explicit_nonce,
            &sf_record.ciphertext,
        )?;

        tracing::info!("Proxy-TLS done");
        let output = TlsOutput {
            keys: refs.keys,
            tls_transcript,
        };

        Ok((
            self.ctx,
            self.vm,
            output,
            self.cf_vd_check,
            self.sf_vd_check,
        ))
    }
}

/// Requires the prover's byte count to match what the verifier relayed.
///
/// `ProxyFinished` is sent only after both directions finish, so there is no
/// legitimate prefix difference left. A mismatch means the peers disagree
/// about the stream — for example, server data after `close_notify` or a
/// partial final record.
fn ensure_equal(recorded: &[u8], claim: u64, direction: &str) -> Result<(), TlsnError> {
    let claim = usize::try_from(claim).map_err(|_| {
        TlsnError::internal().with_msg(format!(
            "{direction}: prover claims an unrepresentable byte count"
        ))
    })?;

    if claim != recorded.len() {
        return Err(TlsnError::internal().with_msg(format!(
            "{direction}: prover claims {claim} bytes but {} were relayed",
            recorded.len()
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ensure_equal;

    #[test]
    fn equal_claim_passes() {
        assert!(ensure_equal(b"abcdef", 6, "recv").is_ok());
    }

    #[test]
    fn shorter_claim_is_rejected() {
        assert!(ensure_equal(b"abcdef", 4, "recv").is_err());
    }

    #[test]
    fn longer_claim_is_rejected() {
        assert!(ensure_equal(b"abcdef", 7, "recv").is_err());
        assert!(ensure_equal(b"abcdef", 7, "sent").is_err());
    }

    #[test]
    fn empty_claim_is_rejected() {
        assert!(ensure_equal(b"abcdef", 0, "recv").is_err());
    }

    #[test]
    fn unrepresentable_claim_is_rejected() {
        assert!(ensure_equal(b"abcdef", u64::MAX, "recv").is_err());
    }
}
