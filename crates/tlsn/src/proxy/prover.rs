use crate::{
    Error as TlsnError, TlsOutput,
    deps::ProverZk,
    proxy::{References, alloc_ghash_key},
};
use cipher::{Cipher, aes::Aes128};
use hmac_sha256::{Mode, Prf};
use mpz_common::Context;
use mpz_memory_core::{Array, MemoryExt, ViewExt, binary::U8};
use mpz_vm_core::Execute;
use serio::SinkExt;
use tlsn_core::{
    SessionKeys,
    config::tls_commit::{NetworkSetting, proxy::ProxyTlsConfig},
    transcript::TlsTranscript,
};
use tracing::debug;

#[derive(Debug)]
pub(crate) struct ProxyProver {
    defer_decryption_from_start: bool,
    ctx: Context,
    vm: ProverZk,
    prf: Prf,
    refs: Option<References>,
}

impl ProxyProver {
    pub(crate) fn new(config: &ProxyTlsConfig, vm: ProverZk, ctx: Context) -> Self {
        let prf_mode = match config.network() {
            NetworkSetting::Bandwidth => Mode::Normal,
            NetworkSetting::Latency => Mode::Reduced,
        };

        let prf = Prf::new(prf_mode, true);
        let defer_decryption_from_start = config.defer_decryption_from_start();

        Self {
            defer_decryption_from_start,
            ctx,
            vm,
            prf,
            refs: None,
        }
    }

    pub(crate) fn defer_decryption_from_start(&self) -> bool {
        self.defer_decryption_from_start
    }

    pub(crate) fn alloc(&mut self) -> Result<(), TlsnError> {
        let vm = &mut self.vm;

        let pms: Array<U8, 32> = vm.alloc().map_err(|e| {
            TlsnError::internal()
                .with_msg("pms allocation failed")
                .with_source(e)
        })?;

        vm.mark_private(pms)
            .map_err(|e| TlsnError::internal().with_source(e))?;

        let prf_output = self.prf.alloc(vm, pms).map_err(|e| {
            TlsnError::internal()
                .with_msg("prf allocation failed")
                .with_source(e)
        })?;

        let mut decrypt = Aes128::default();
        decrypt.set_key(prf_output.keys.server_write_key);
        decrypt.set_iv(prf_output.keys.server_iv);

        let server_write_mac_key = alloc_ghash_key(vm, &mut decrypt)?;

        let keys = SessionKeys {
            client_write_key: prf_output.keys.client_write_key,
            client_write_iv: prf_output.keys.client_iv,
            server_write_key: prf_output.keys.server_write_key,
            server_write_iv: prf_output.keys.server_iv,
            server_write_mac_key,
        };

        let cf_vd = vm
            .decode(prf_output.cf_vd)
            .map_err(|e| TlsnError::internal().with_source(e))?;
        let sf_vd = vm
            .decode(prf_output.sf_vd)
            .map_err(|e| TlsnError::internal().with_source(e))?;

        let refs = References {
            pms,
            keys,
            cf_vd,
            sf_vd,
        };
        self.refs = Some(refs);

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
        session_hash: Vec<u8>,
        cf_hash: Vec<u8>,
        sf_hash: Vec<u8>,
        tls_transcript: TlsTranscript,
    ) -> Result<(Context, ProverZk, TlsOutput), TlsnError> {
        let refs = self.refs.expect("key refs should be available");

        self.ctx
            .io_mut()
            .send(session_hash.clone())
            .await
            .map_err(|e| {
                TlsnError::io()
                    .with_msg("send session_hash to verifier failed")
                    .with_source(e)
            })?;
        self.ctx.io_mut().send(cf_hash.clone()).await.map_err(|e| {
            TlsnError::io()
                .with_msg("send cf_hash to verifier failed")
                .with_source(e)
        })?;
        self.ctx.io_mut().send(sf_hash.clone()).await.map_err(|e| {
            TlsnError::io()
                .with_msg("send sf_hash to verifier failed")
                .with_source(e)
        })?;
        tracing::debug!("sent handshake hashes");

        let cf_hash: [u8; 32] = cf_hash
            .try_into()
            .map_err(|_| TlsnError::internal().with_msg("cf_hash has wrong length"))?;
        let sf_hash: [u8; 32] = sf_hash
            .try_into()
            .map_err(|_| TlsnError::internal().with_msg("sf_hash has wrong length"))?;

        let pms: [u8; 32] = pms
            .try_into()
            .map_err(|_| TlsnError::internal().with_msg("pms has wrong length"))?;

        let tlsn_core::connection::CertBinding::V1_2(binding) =
            tls_transcript.certificate_binding()
        else {
            return Err(
                TlsnError::internal().with_msg("version of certifiacte binding is not supported")
            );
        };

        tracing::debug!("computing PRF...");
        self.vm
            .assign(refs.pms, pms)
            .map_err(|e| TlsnError::internal().with_source(e))?;
        self.vm
            .commit(refs.pms)
            .map_err(|e| TlsnError::internal().with_source(e))?;

        self.prf
            .set_ms_seed(session_hash)
            .map_err(|e| TlsnError::internal().with_source(e))?;

        self.prf
            .set_client_random(binding.client_random)
            .map_err(|e| TlsnError::internal().with_source(e))?;

        self.prf
            .set_server_random(binding.server_random)
            .map_err(|e| TlsnError::internal().with_source(e))?;

        while self.prf.wants_flush() {
            self.prf
                .flush(&mut self.vm)
                .map_err(|e| TlsnError::internal().with_source(e))?;
            self.vm
                .execute_all(&mut self.ctx)
                .await
                .map_err(|e| TlsnError::internal().with_source(e))?;
        }

        self.prf
            .set_cf_hash(cf_hash)
            .map_err(|e| TlsnError::internal().with_source(e))?;

        while self.prf.wants_flush() {
            self.prf
                .flush(&mut self.vm)
                .map_err(|e| TlsnError::internal().with_source(e))?;
            self.vm
                .execute_all(&mut self.ctx)
                .await
                .map_err(|e| TlsnError::internal().with_source(e))?;
        }

        self.prf
            .set_sf_hash(sf_hash)
            .map_err(|e| TlsnError::internal().with_source(e))?;

        while self.prf.wants_flush() {
            self.prf
                .flush(&mut self.vm)
                .map_err(|e| TlsnError::internal().with_source(e))?;
            self.vm
                .execute_all(&mut self.ctx)
                .await
                .map_err(|e| TlsnError::internal().with_source(e))?;
        }

        debug!("Proxy TLS done");

        let output = TlsOutput {
            keys: refs.keys,
            tls_transcript,
        };
        Ok((self.ctx, self.vm, output))
    }
}
