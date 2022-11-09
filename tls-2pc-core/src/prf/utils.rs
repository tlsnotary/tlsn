#![allow(dead_code)]

use digest::Digest;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::convert::TryInto;

type HmacSha256 = Hmac<Sha256>;

pub fn hmac_sha256(key: &[u8], input: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(input);
    let out = mac.finalize().into_bytes();
    out[..32]
        .try_into()
        .expect("expected output to be 32 bytes")
}

pub fn generate_hmac_pads(input: &[u8]) -> ([u8; 64], [u8; 64]) {
    let mut ipad = [0x36_u8; 64];
    let mut opad = [0x5c_u8; 64];

    for (ipad, input) in ipad.iter_mut().zip(input.iter()) {
        *ipad ^= *input;
    }
    for (opad, input) in opad.iter_mut().zip(input.iter()) {
        *opad ^= *input;
    }
    (ipad, opad)
}

pub fn seed_ms(client_random: &[u8; 32], server_random: &[u8; 32]) -> [u8; 77] {
    let mut seed = [0u8; 77];
    seed[..13].copy_from_slice(b"master secret");
    seed[13..45].copy_from_slice(client_random);
    seed[45..].copy_from_slice(server_random);
    seed
}

pub fn seed_ke(client_random: &[u8; 32], server_random: &[u8; 32]) -> [u8; 77] {
    let mut seed = [0u8; 77];
    seed[..13].copy_from_slice(b"key expansion");
    seed[13..45].copy_from_slice(server_random);
    seed[45..].copy_from_slice(client_random);
    seed
}

pub fn seed_cf(handshake_blob: &[u8]) -> [u8; 47] {
    let mut hasher = Sha256::new();
    hasher.update(handshake_blob);
    let mut seed = [0u8; 47];
    seed[..15].copy_from_slice(b"client finished");
    seed[15..].copy_from_slice(hasher.finalize().as_slice());
    seed
}

pub fn seed_sf(handshake_blob: &[u8]) -> [u8; 47] {
    let mut hasher = Sha256::new();
    hasher.update(handshake_blob);
    let mut seed = [0u8; 47];
    seed[..15].copy_from_slice(b"server finished");
    seed[15..].copy_from_slice(hasher.finalize().as_slice());
    seed
}
