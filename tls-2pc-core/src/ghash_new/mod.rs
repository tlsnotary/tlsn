//! This module implements the AES-GCM's GHASH function in a secure two-party computation (2PC)
//! setting using 1-out-of-2 Oblivious Transfer (OT). The parties start with their secret XOR
//! shares of H (the GHASH key) and at the end each gets their XOR share of the GHASH output. The
//! method is decribed here <https://tlsnotary.org/how_it_works#section4>.
//!
//! At first we will convert the XOR (additive) share of `H`, into a multiplicative share. This
//! allows us to compute all the necessary powers of `H^n` locally. Then each of these
//! multiplicative shares will be converted back into additive shares. This way, we can batch
//! nearly all the oblivious transfers, which are needed per conversion, and reduce the round
//! complexity of the protocol.
//!
//! On the whole, we need a single additive-to-multiplicative (A2M) and `n`, which is the number of
//! blocks of the ciphertext, multiplicative-to-additive (M2A) conversions. Finally, having
//! additive shares of `H^n` for all needed `n`, we can compute an additive share of the MAC.

mod receiver;
mod sender;
use gf2_128::{compute_powers, mul, AddShare, MaskedPartialValue, MulShare};
pub use {receiver::GhashReceiver, sender::GhashSender};

