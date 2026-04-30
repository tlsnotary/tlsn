use crate::{
    Error as TlsnError, TlsOutput,
    deps::VerifierZk,
    proxy::{MsVisibility, References, VerifyDataCheck, alloc_proxy_refs},
};
use hmac_sha256::Prf;
use mpz_common::Context;
use mpz_memory_core::MemoryExt;
use mpz_vm_core::Execute;
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

    pub(crate) async fn finalize(
        mut self,
        sent: &[u8],
        recv: &[u8],
        conn_time: u64,
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
        let tls_transcript =
            TlsTranscript::parse(conn_time, sent, recv, &[], &[]).map_err(|e| {
                TlsnError::internal()
                    .with_msg("verifier could not build tls transcript")
                    .with_source(e)
            })?;
        tracing::debug!("successfully parsed transcript");

        let mut refs = self.refs.expect("key refs should be available");

        let cf_hash: [u8; 32] = tls_transcript
            .cf_hash()
            .expect("cf_hash should be available")
            .try_into()
            .expect("cf_hash should be 32 bytes");

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
        let sf_hash: [u8; 32] = tls_transcript
            .sf_hash(&cf_vd)
            .expect("sf_hash should be available")
            .try_into()
            .expect("sf_hash should be 32 bytes");

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

        let cf_vd_record = tls_transcript.cf_vd();
        self.cf_vd_check.assign(
            &mut self.vm,
            &cf_vd_record.explicit_nonce,
            &cf_vd_record.ciphertext,
        )?;

        let sf_vd_record = tls_transcript.sf_vd();
        self.sf_vd_check.assign(
            &mut self.vm,
            &sf_vd_record.explicit_nonce,
            &sf_vd_record.ciphertext,
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
