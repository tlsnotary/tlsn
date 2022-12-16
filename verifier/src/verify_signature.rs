use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

/// verify that a P256 signature is over the message
pub fn verify_sig_p256(msg: &Vec<u8>, pubkey: &Vec<u8>, sig: &Vec<u8>) -> bool {
    let Ok(vk) = VerifyingKey::from_sec1_bytes(pubkey) else {
        return false;
    };
    let Ok(signature) = Signature::from_der(sig) else {
        return false;
    };
    let Ok(_) = vk.verify(msg, &signature) else {
        return false;
    };
    true
}

pub fn verify_sig_bn254(msg: &Vec<u8>, pubkey: &Vec<u8>, sig: &Vec<u8>) -> bool {
    true
}

pub fn verify_sig_bls12381(msg: &Vec<u8>, pubkey: &Vec<u8>, sig: &Vec<u8>) -> bool {
    true
}
