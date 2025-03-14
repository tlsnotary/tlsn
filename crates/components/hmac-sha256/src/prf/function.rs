use crate::hmac::HmacSha256;
use mpz_circuits::types::U8;
use mpz_vm_core::memory::{Array, Vector};

#[derive(Debug)]
pub(crate) struct Prf {
    a: Vec<A>,
    p: Vec<P>,
}

impl Prf {
    const MS_LABEL: &[u8] = b"master secret";
    const KEY_LABEL: &[u8] = b"key expansion";
    const CF_LABEL: &[u8] = b"client finished";
    const SF_LABEL: &[u8] = b"server finished";

    pub(crate) fn new_master_secret(key: Vector<U8>, seed: Vector<U8>) -> Self {
        todo!()
    }

    pub(crate) fn new_key_expansion(key: Vector<U8>, seed: Vector<U8>) -> Self {
        todo!()
    }

    pub(crate) fn new_client_finished(key: Vector<U8>, seed: Vector<U8>) -> Self {
        todo!()
    }

    pub(crate) fn new_server_finished(key: Vector<U8>, seed: Vector<U8>) -> Self {
        todo!()
    }
}

#[derive(Debug)]
struct A {
    index: usize,
    hmac: HmacSha256,
    output: Array<U8, 32>,
}

impl A {
    pub(crate) fn compute(&mut self) {
        todo!()
    }
}

#[derive(Debug)]
struct P {
    index: usize,
    hmac: HmacSha256,
    output: Array<U8, 32>,
}

impl P {
    pub(crate) fn compute(&mut self) {
        todo!()
    }
}
