use crate::Error as TlsnError;
use cipher::{Cipher, aes::Aes128};
use futures::{AsyncRead, ready};
use mpz_core::bitvec::BitVec;
use mpz_memory_core::{
    Array, DecodeFutureTyped, MemoryExt, ViewExt,
    binary::{Binary, U8},
};
use mpz_vm_core::Vm;
use std::{io, pin::Pin, task::Poll};

mod parser;
pub(crate) use parser::TlsParser;

mod prover;
pub(crate) use prover::ProxyProver;

mod verifier;
use tlsn_core::SessionKeys;
pub(crate) use verifier::ProxyVerifier;

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

#[derive(Debug)]
struct References {
    pub(crate) pms: Array<U8, 32>,
    pub(crate) keys: SessionKeys,
    pub(crate) cf_vd: DecodeFutureTyped<BitVec, [u8; 12]>,
    pub(crate) sf_vd: DecodeFutureTyped<BitVec, [u8; 12]>,
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
