#![allow(dead_code)]

use digest::Digest;
use hmac::{Hmac, Mac};
use num::BigUint;
use sha2::Sha256;
use std::convert::TryInto;

type HmacSha256 = Hmac<Sha256>;

pub fn add_p256_shares(share_a: &[u8; 32], share_b: &[u8; 32]) -> [u8; 32] {
    let p = BigUint::parse_bytes(
        b"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        16,
    )
    .unwrap();
    let share_a = BigUint::from_bytes_be(share_a);
    let share_b = BigUint::from_bytes_be(share_b);
    let sum = (share_a + share_b) % &p;

    sum.to_bytes_be().try_into().unwrap()
}

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

pub fn compute_ms(client_random: &[u8; 32], server_random: &[u8; 32], pms: &[u8]) -> [u8; 48] {
    let seed = seed_ms(client_random, server_random);
    let a1 = hmac_sha256(pms, &seed);
    let a2 = hmac_sha256(pms, &a1);
    let mut a1_seed = [0u8; 109];
    a1_seed[..32].copy_from_slice(&a1);
    a1_seed[32..].copy_from_slice(&seed);
    let mut a2_seed = [0u8; 109];
    a2_seed[..32].copy_from_slice(&a2);
    a2_seed[32..].copy_from_slice(&seed);
    let p1 = hmac_sha256(pms, &a1_seed);
    let p2 = hmac_sha256(pms, &a2_seed);
    let mut ms = [0u8; 48];
    ms[..32].copy_from_slice(&p1);
    ms[32..].copy_from_slice(&p2[..16]);
    ms
}

pub fn compute_client_finished_vd(ms: [u8; 48], handshake_hash: [u8; 32]) -> [u8; 12] {
    let mut seed = [0u8; 47];
    seed[..15].copy_from_slice(b"client finished");
    seed[15..].copy_from_slice(&handshake_hash);
    let a1 = hmac_sha256(&ms, &seed);
    let mut a1_seed = [0u8; 79];
    a1_seed[..32].copy_from_slice(&a1);
    a1_seed[32..].copy_from_slice(&seed);
    let p1 = hmac_sha256(&ms, &a1_seed);

    let mut vd = [0u8; 12];
    vd.copy_from_slice(&p1[..12]);

    vd
}

pub fn compute_server_finished_vd(ms: [u8; 48], handshake_hash: [u8; 32]) -> [u8; 12] {
    let mut seed = [0u8; 47];
    seed[..15].copy_from_slice(b"server finished");
    seed[15..].copy_from_slice(&handshake_hash);
    let a1 = hmac_sha256(&ms, &seed);
    let mut a1_seed = [0u8; 79];
    a1_seed[..32].copy_from_slice(&a1);
    a1_seed[32..].copy_from_slice(&seed);
    let p1 = hmac_sha256(&ms, &a1_seed);

    let mut vd = [0u8; 12];
    vd.copy_from_slice(&p1[..12]);

    vd
}

/// Expands pre-master secret into session key using TLS 1.2 PRF
/// Returns session keys
pub fn key_expansion_tls12(
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    pms: &[u8],
) -> ([u8; 16], [u8; 16], [u8; 4], [u8; 4]) {
    let ms = compute_ms(client_random, server_random, pms);

    // expand ms into session keys
    let seed = seed_ke(client_random, server_random);
    let a1 = hmac_sha256(&ms, &seed);
    let a2 = hmac_sha256(&ms, &a1);
    let mut a1_seed = [0u8; 109];
    a1_seed[..32].copy_from_slice(&a1);
    a1_seed[32..].copy_from_slice(&seed);
    let mut a2_seed = [0u8; 109];
    a2_seed[..32].copy_from_slice(&a2);
    a2_seed[32..].copy_from_slice(&seed);
    let p1 = hmac_sha256(&ms, &a1_seed);
    let p2 = hmac_sha256(&ms, &a2_seed);
    let mut ek = [0u8; 40];
    ek[..32].copy_from_slice(&p1);
    ek[32..].copy_from_slice(&p2[..8]);

    let mut cwk = [0u8; 16];
    cwk.copy_from_slice(&ek[..16]);
    let mut swk = [0u8; 16];
    swk.copy_from_slice(&ek[16..32]);
    let mut civ = [0u8; 4];
    civ.copy_from_slice(&ek[32..36]);
    let mut siv = [0u8; 4];
    siv.copy_from_slice(&ek[36..]);

    (cwk, swk, civ, siv)
}
