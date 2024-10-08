use mpz_common::Context;
use mpz_memory_core::{binary::U8, Array};
use tlsn_universal_hash::ghash::Ghash;

use crate::cipher::{Aes128, Cipher};

mod error;

pub struct MpcAesGcm<S> {
    key: <Aes128 as Cipher>::Key,
    iv: Array<U8, 4>,
    cipher: Aes128
    mac: Ghash<S>,
}

impl<C: Cipher, U: UniversalHash, Ctx: Context> MpcAesGcm<C, U> {
    pub fn new() -> Self {
        todo!()
    }
}

impl<Ctx: Context, Vm: VmExt> AeadCipher<Ctx, Vm> for MpcAesGcm {}
