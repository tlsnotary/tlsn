#!/usr/bin/env -S cargo +nightly -Zscript
---
[package]
name = "generate_test_data"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
sha2 = "0.10"
rand = "0.8"
chrono = "0.4"
---
use chrono::Datelike;
use chrono::Local;
use rand::RngCore;
use sha2::{Digest, Sha256};

fn main() {
    // 1. Birthdate string (fixed)
    let dob_str = "1985-03-12"; // 10 bytes long

    let proof_date = Local::now().date_naive();
    let proof_year = proof_date.year();
    let proof_month = proof_date.month();
    let proof_day = proof_date.day();

    // 2. Generate random 16-byte blinder
    let mut blinder = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut blinder);

    // 3. Concatenate blinder + dob string bytes
    let mut preimage = Vec::with_capacity(26);
    preimage.extend_from_slice(dob_str.as_bytes());
    preimage.extend_from_slice(&blinder);

    // 4. Hash it
    let hash = Sha256::digest(&preimage);

    let blinder = blinder
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let committed_hash = hash
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(", ");

    println!(
        "
// Private input
let date_of_birth = \"{dob_str}\";
let blinder = [{blinder}];

// Public input
let proof_date = date::Date {{ year: {proof_year}, month: {proof_month}, day: {proof_day} }};
let committed_hash = [{committed_hash}];

main(proof_date, committed_hash, date_of_birth, blinder);
"
    );
}
