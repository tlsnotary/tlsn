//! This module implements the M2A and A2M algorithm for field elements of GF(2^128), using
//! oblivious transfer.
//!
//! * M2A: Implementation of chapter 4.1 in <https://link.springer.com/content/pdf/10.1007/3-540-48405-1_8.pdf>
//! * A2M: Adaptation of chapter 4 in <https://www.cs.umd.edu/~fenghao/paper/modexp.pdf>

mod aio;
pub mod core;
