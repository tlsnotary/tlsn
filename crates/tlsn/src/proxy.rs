//! Proxy-specific proving and verifying logic.

use crate::Error as TlsnError;
use cipher::{Cipher, Keystream, aes::Aes128};
use futures::{AsyncRead, ready};
use hmac_sha256::Prf;
use mpc_tls::SessionKeys;
use mpz_core::bitvec::BitVec;
use mpz_memory_core::{
    Array, DecodeFutureTyped, MemoryExt, Vector, ViewExt,
    binary::{Binary, U8},
};
use mpz_vm_core::Vm;
use std::{io, pin::Pin, task::Poll};

mod prover;
pub(crate) use prover::ProxyProver;

mod verifier;
pub(crate) use verifier::ProxyVerifier;

const AES_GCM_START_COUNTER: u32 = 2;

fn alloc_ghash_key(
    vm: &mut dyn Vm<Binary>,
    cipher: &mut Aes128,
) -> Result<Array<U8, 16>, TlsnError> {
    let zero_block: Array<U8, 16> = vm
        .alloc()
        .map_err(|e| TlsnError::internal().with_source(e))?;
    vm.mark_public(zero_block)
        .map_err(|e| TlsnError::internal().with_source(e))?;
    vm.assign(zero_block, [0u8; 16])
        .map_err(|e| TlsnError::internal().with_source(e))?;
    vm.commit(zero_block)
        .map_err(|e| TlsnError::internal().with_source(e))?;

    let ghash_key = cipher
        .alloc_block(vm, zero_block)
        .map_err(|e| TlsnError::internal().with_source(e))?;

    Ok(ghash_key)
}

/// Controls how the master secret is marked in the VM during allocation.
enum MsVisibility {
    /// Prover knows the master secret value.
    Private,
    /// Verifier is blind to the master secret value.
    Blind,
}

/// Allocates all proxy-mode resources in the VM: master secret, PRF-derived
/// keys, ciphers, GHASH key, verify-data decode futures, and verify-data
/// checks.
fn alloc_proxy_refs<V: Vm<Binary>>(
    vm: &mut V,
    prf: &mut Prf,
    cf_vd_check: &mut VerifyDataCheck,
    sf_vd_check: &mut VerifyDataCheck,
    ms_visibility: MsVisibility,
) -> Result<References, TlsnError> {
    let ms: Array<U8, 48> = vm.alloc().map_err(|e| {
        TlsnError::internal()
            .with_msg("ms allocation failed")
            .with_source(e)
    })?;

    match ms_visibility {
        MsVisibility::Private => vm.mark_private(ms),
        MsVisibility::Blind => vm.mark_blind(ms),
    }
    .map_err(|e| TlsnError::internal().with_source(e))?;

    let prf_output = prf.alloc_ms(vm, ms).map_err(|e| {
        TlsnError::internal()
            .with_msg("prf allocation failed")
            .with_source(e)
    })?;

    let mut encrypt = Aes128::default();
    encrypt.set_key(prf_output.keys.client_write_key);
    encrypt.set_iv(prf_output.keys.client_iv);

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
    _ = vm
        .decode(prf_output.sf_vd)
        .map_err(|e| TlsnError::internal().with_source(e))?;

    cf_vd_check.alloc(vm, &mut encrypt, prf_output.cf_vd)?;
    sf_vd_check.alloc(vm, &mut decrypt, prf_output.sf_vd)?;

    Ok(References { ms, keys, cf_vd })
}

#[derive(Debug)]
struct References {
    pub(crate) ms: Array<U8, 48>,
    pub(crate) keys: SessionKeys,
    pub(crate) cf_vd: DecodeFutureTyped<BitVec, [u8; 12]>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct TlsBytes {
    pub(crate) tls_sent: Vec<u8>,
    pub(crate) tls_recv: Vec<u8>,
    pub(crate) app_sent: Vec<u8>,
    pub(crate) app_recv: Vec<u8>,
}

/// An [`AsyncRead`] adapter that records all bytes read into a buffer.
///
/// Used to intercept TLS traffic as it flows through the proxy,
/// extending the parser's transcript buffers on the fly.
pub(crate) struct InspectReader<'a, R> {
    inner: R,
    buf: &'a mut Vec<u8>,
    first_read: Option<u64>,
}

impl<'a, R> InspectReader<'a, R> {
    pub(crate) fn new(inner: R, buf: &'a mut Vec<u8>) -> Self {
        Self {
            inner,
            buf,
            first_read: None,
        }
    }

    pub(crate) fn first_read(&self) -> Option<u64> {
        self.first_read
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for InspectReader<'_, R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let n = ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
        if this.first_read.is_none() && n > 0 {
            let now = web_time::UNIX_EPOCH
                .elapsed()
                .expect("system time is available")
                .as_secs();
            this.first_read = Some(now);
        }
        this.buf.extend_from_slice(&buf[..n]);
        Poll::Ready(Ok(n))
    }
}

#[derive(Debug, Default)]
pub(crate) struct VerifyDataCheck {
    state: InnerState,
}

#[derive(Default)]
enum InnerState {
    #[default]
    Init,
    Alloc {
        keystream: Keystream<Array<U8, 8>, Array<U8, 4>, Array<U8, 16>>,
        ciphertext_vd: Array<U8, 16>,
        expected_vd: Array<U8, 12>,
        actual_vd: Vector<U8>,
    },
    Assigned {
        expected_vd: Array<U8, 12>,
        actual_vd: Array<U8, 12>,
    },
}

opaque_debug::implement!(InnerState);

impl VerifyDataCheck {
    pub(crate) fn alloc(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        cipher: &mut Aes128,
        expected_vd: Array<U8, 12>,
    ) -> Result<(), TlsnError> {
        let InnerState::Init = self.state else {
            return Err(TlsnError::internal().with_msg("unable to alloc verify data check"));
        };

        let ciphertext_vd: Array<U8, 16> = vm
            .alloc()
            .map_err(|e| TlsnError::internal().with_source(e))?;
        vm.mark_public(ciphertext_vd)
            .map_err(|e| TlsnError::internal().with_source(e))?;

        let keystream = cipher
            .alloc_keystream(vm, 16)
            .map_err(|e| TlsnError::internal().with_source(e))?;
        let actual_vd = keystream
            .apply(vm, Vector::from(ciphertext_vd))
            .map_err(|e| TlsnError::internal().with_source(e))?;

        drop(
            vm.decode(actual_vd)
                .map_err(|e| TlsnError::internal().with_source(e))?,
        );

        self.state = InnerState::Alloc {
            keystream,
            ciphertext_vd,
            expected_vd,
            actual_vd,
        };
        Ok(())
    }

    pub(crate) fn assign(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        explicit_nonce: &[u8],
        ciphertext_vd: &[u8],
    ) -> Result<(), TlsnError> {
        let InnerState::Alloc {
            expected_vd,
            ciphertext_vd: ciphertext_vd_ref,
            actual_vd,
            keystream,
        } = &mut self.state
        else {
            return Err(TlsnError::internal().with_msg("unable to assign verify data check"));
        };
        let explicit_nonce = explicit_nonce
            .try_into()
            .map_err(|e| TlsnError::internal().with_source(e))?;
        let ciphertext_vd: [u8; 16] = ciphertext_vd
            .try_into()
            .map_err(|e| TlsnError::internal().with_source(e))?;

        keystream
            .assign(vm, explicit_nonce, || AES_GCM_START_COUNTER.to_be_bytes())
            .map_err(|e| TlsnError::internal().with_source(e))?;

        vm.assign(*ciphertext_vd_ref, ciphertext_vd)
            .map_err(|e| TlsnError::internal().with_source(e))?;
        vm.commit(*ciphertext_vd_ref)
            .map_err(|e| TlsnError::internal().with_source(e))?;

        // split off the handshake header first.
        let actual_vd = actual_vd.split_off(4);
        let actual_vd =
            Array::try_from(actual_vd).map_err(|e| TlsnError::internal().with_source(e))?;

        self.state = InnerState::Assigned {
            expected_vd: *expected_vd,
            actual_vd,
        };

        Ok(())
    }

    pub(crate) fn check(self, vm: &mut dyn Vm<Binary>) -> Result<(), TlsnError> {
        let InnerState::Assigned {
            expected_vd,
            actual_vd,
        } = self.state
        else {
            return Err(TlsnError::internal().with_msg("unable to check verify data"));
        };

        let expected_vd = vm
            .get(expected_vd)
            .map_err(|e| TlsnError::internal().with_source(e))?
            .ok_or(TlsnError::internal().with_msg("could not retrieve expected verify data"))?;

        let actual_vd = vm
            .get(actual_vd)
            .map_err(|e| TlsnError::internal().with_source(e))?
            .ok_or(TlsnError::internal().with_msg("could not retrieve actual verify data"))?;

        if expected_vd != actual_vd {
            return Err(TlsnError::user().with_msg("verify data check failed"));
        }

        Ok(())
    }
}
