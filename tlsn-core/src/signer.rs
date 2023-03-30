#[derive(Default)]
pub struct Signer {}

impl Signer {
    pub fn sign(&self, msg: Vec<u8>) -> &[u8] {
        &[0u8; 32]
    }
}
