mod error;

pub struct MpcAesGcm<C, U> {
    key: C::Key,
    iv: Array<U8>,
    cipher: C,
    mac: U,
}

impl<C: Cipher, U: UniversalHash, Ctx: Context> MpcAesGcm<C, U> {
    pub fn new() -> Self {
        todo!()
    }

    pub fn set_key(key: C::Key) {
        todo!()
    }

    pub fn setup() {
        todo!()
    }

    pub fn preprocess() {
        todo!()
    }

    pub fn encrypt(
        vm: &mut VmExt,
        ctx: &mut Ctx,
        ciphertext: Vector<U8>,
        aad: Vector<U8>,
    ) -> Result<Vector<U8>, MpcAeadError> {
        todo!()
    }

    pub fn decrypt() {
        todo!()
    }

    pub fn decode_key() {
        todo!()
    }
}
