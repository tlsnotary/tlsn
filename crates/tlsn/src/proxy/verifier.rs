use crate::{
    Error as TlsnError, TlsOutput,
    deps::VerifierZk,
    proxy::{References, TlsParser, alloc_ghash_key},
};
use cipher::{Cipher, aes::Aes128};
use hmac_sha256::Prf;
use mpz_common::Context;
use mpz_memory_core::{Array, MemoryExt, ViewExt, binary::U8};
use mpz_vm_core::Execute;
use serio::stream::IoStreamExt;
use tlsn_core::SessionKeys;

pub(crate) struct ProxyVerifier {
    ctx: Context,
    vm: VerifierZk,
    prf: Prf,
    refs: Option<References>,
}

impl ProxyVerifier {
    pub(crate) fn new(prf: Prf, vm: VerifierZk, ctx: Context) -> Self {
        Self {
            ctx,
            vm,
            prf,
            refs: None,
        }
    }

    pub(crate) fn alloc(&mut self) -> Result<(), TlsnError> {
        let vm = &mut self.vm;

        let pms: Array<U8, 32> = vm.alloc().map_err(|e| {
            TlsnError::internal()
                .with_msg("pms allocation failed")
                .with_source(e)
        })?;

        vm.mark_blind(pms)
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
        mut parser: TlsParser,
        conn_time: u64,
    ) -> Result<(Context, VerifierZk, TlsOutput), TlsnError> {
        let mut refs = self.refs.expect("key refs should be available");

        let session_hash: Vec<u8> = self.ctx.io_mut().expect_next().await.map_err(|e| {
            TlsnError::io()
                .with_msg("receive session_hash from prover failed")
                .with_source(e)
        })?;
        let cf_hash: Vec<u8> = self.ctx.io_mut().expect_next().await.map_err(|e| {
            TlsnError::io()
                .with_msg("receive cf_hash from prover failed")
                .with_source(e)
        })?;
        let sf_hash: Vec<u8> = self.ctx.io_mut().expect_next().await.map_err(|e| {
            TlsnError::io()
                .with_msg("receive sf_hash from prover failed")
                .with_source(e)
        })?;
        tracing::debug!("received handshake hashes");

        let cf_hash: [u8; 32] = cf_hash
            .try_into()
            .map_err(|_| TlsnError::internal().with_msg("cf_hash has wrong length"))?;
        let sf_hash: [u8; 32] = sf_hash
            .try_into()
            .map_err(|_| TlsnError::internal().with_msg("sf_hash has wrong length"))?;

        let handshake = parser.parse_handshake().map_err(|e| {
            TlsnError::io()
                .with_msg("failed to parse handshake")
                .with_source(e)
        })?;
        tracing::debug!("successfully parsed handshake");

        let tlsn_core::connection::CertBinding::V1_2(binding) = handshake.binding else {
            return Err(
                TlsnError::internal().with_msg("version of certifiacte binding is not supported")
            );
        };

        tracing::debug!("computing PRF...");
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

        tracing::debug!("decoding verify data...");
        let cf_vd = refs
            .cf_vd
            .try_recv()
            .map_err(|e| TlsnError::internal().with_source(e))?
            .ok_or(TlsnError::internal().with_msg("unable to receive cf_vd from decoding"))?;

        let sf_vd = refs
            .sf_vd
            .try_recv()
            .map_err(|e| TlsnError::internal().with_source(e))?
            .ok_or(TlsnError::internal().with_msg("unable to receive sf_vd from decoding"))?;

        parser.set_time(conn_time);

        parser.set_cf_vd(&cf_vd);
        parser.set_sf_vd(&sf_vd);

        let tls_transcript = parser.build().map_err(|e| {
            TlsnError::internal()
                .with_msg("verifier could not build tls transcript")
                .with_source(e)
        })?;
        tracing::debug!("sucessfully parsed transcript");

        let output = TlsOutput {
            keys: refs.keys,
            tls_transcript,
        };

        Ok((self.ctx, self.vm, output))
    }
}
