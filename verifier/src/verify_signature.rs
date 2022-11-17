use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

/// verify that a P256 signature is over the message
pub fn verify_sig_p256(msg: &Vec<u8>, pubkey: &Vec<u8>, sig: &Vec<u8>) -> bool {
    // TODO need to look into exactly how to deserialize key/sig
    let vk = VerifyingKey::from_sec1_bytes(pubkey).unwrap();
    let signature = Signature::from_der(sig).unwrap();
    if vk.verify(msg, &signature).is_err() {
        return false;
    } else {
        return true;
    }
}

pub fn verify_sig_bn254(msg: &Vec<u8>, pubkey: &Vec<u8>, sig: &Vec<u8>) -> bool {
    true
}

pub fn verify_sig_bls12381(msg: &Vec<u8>, pubkey: &Vec<u8>, sig: &Vec<u8>) -> bool {
    true
}
