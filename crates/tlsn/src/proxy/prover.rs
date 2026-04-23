use crate::{
    Error as TlsnError, TlsOutput,
    deps::ProverZk,
    proxy::{PmsVisibility, References, TlsBytes, VerifyDataCheck, alloc_proxy_refs},
};
use hmac_sha256::{MSMode, NetworkMode, Prf, PrfConfig};
use mpz_common::Context;
use mpz_memory_core::MemoryExt;
use mpz_vm_core::Execute;
use tlsn_core::transcript::TlsTranscript;

#[derive(Debug)]
pub(crate) struct ProxyProver {
    ctx: Context,
    vm: ProverZk,
    prf: Prf,
    refs: Option<References>,
    cf_vd_check: VerifyDataCheck,
    sf_vd_check: VerifyDataCheck,
}

impl ProxyProver {
    pub(crate) fn new(vm: ProverZk, ctx: Context) -> Self {
        let prf_config = PrfConfig::new(NetworkMode::Normal, MSMode::Extended);
        let prf = Prf::new(prf_config);

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
            PmsVisibility::Private,
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
        pms: Vec<u8>,
        time: u64,
        traffic: TlsBytes,
    ) -> Result<(Context, ProverZk, TlsOutput), TlsnError> {
        let mut refs = self.refs.expect("key refs should be available");

        let pms: [u8; 32] = pms
            .try_into()
            .map_err(|_| TlsnError::internal().with_msg("pms has wrong length"))?;

        let session_hash =
            TlsTranscript::compute_session_hash(&traffic.tls_sent, &traffic.tls_recv)
                .map_err(|e| TlsnError::internal().with_source(e))?
                .to_vec();

        let cf_hash = TlsTranscript::compute_cf_hash(&traffic.tls_sent, &traffic.tls_recv)
            .map_err(|e| {
                TlsnError::internal()
                    .with_msg("failed to compute cf_hash")
                    .with_source(e)
            })?;

        let (_version, handshake) = tlsn_core::transcript::TlsTranscript::parse_handshake(
            &traffic.tls_sent,
            &traffic.tls_recv,
        )
        .map_err(|e| {
            TlsnError::io()
                .with_msg("failed to parse handshake")
                .with_source(e)
        })?;
        tracing::debug!("successfully parsed handshake");

        let tlsn_core::connection::CertBinding::V1_2(binding) = handshake.binding else {
            return Err(
                TlsnError::internal().with_msg("version of certificate binding is not supported")
            );
        };

        tracing::debug!("computing PRF...");
        self.vm
            .assign(refs.pms, pms)
            .map_err(|e| TlsnError::internal().with_source(e))?;
        self.vm
            .commit(refs.pms)
            .map_err(|e| TlsnError::internal().with_source(e))?;

        self.prf.set_client_random(binding.client_random);
        self.prf
            .set_server_random(binding.server_random)
            .map_err(|e| TlsnError::internal().with_source(e))?;
        self.prf
            .set_session_hash(session_hash)
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
        let sf_hash = TlsTranscript::compute_sf_hash(&traffic.tls_sent, &traffic.tls_recv, &cf_vd)
            .map_err(|e| {
                TlsnError::internal()
                    .with_msg("failed to compute sf_hash")
                    .with_source(e)
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
        let sf_vd = refs
            .sf_vd
            .try_recv()
            .map_err(|e| TlsnError::internal().with_source(e))?
            .ok_or(TlsnError::internal().with_msg("unable to receive sf_vd from decoding"))?;

        let tls_transcript = tlsn_core::transcript::TlsTranscript::parse(
            time,
            &traffic.tls_sent,
            &traffic.tls_recv,
            &traffic.app_sent,
            &traffic.app_recv,
            &cf_vd,
            &sf_vd,
        )
        .map_err(|e| {
            TlsnError::internal()
                .with_msg("prover could not build tls transcript")
                .with_source(e)
        })?;
        tracing::debug!("successfully parsed transcript");

        let cf_vd_record = tls_transcript
            .sent()
            .first()
            .expect("should be able to get first sent record");
        self.cf_vd_check.assign(
            &mut self.vm,
            &cf_vd_record.explicit_nonce,
            &cf_vd_record.ciphertext,
        )?;

        let sf_vd_record = tls_transcript
            .recv()
            .first()
            .expect("should be able to get first recv record");
        self.sf_vd_check.assign(
            &mut self.vm,
            &sf_vd_record.explicit_nonce,
            &sf_vd_record.ciphertext,
        )?;

        tracing::info!("Proxy TLS done");
        let output = TlsOutput {
            keys: refs.keys,
            tls_transcript,
        };

        Ok((self.ctx, self.vm, output))
    }
}
