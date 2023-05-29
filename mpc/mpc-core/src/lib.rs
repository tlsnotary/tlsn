//! Core types and utilities for MPC protocols
#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]

mod block;
pub mod commit;
pub mod hash;
pub mod serialize;
pub mod utils;
pub mod value;

pub use block::{Block, BlockSerialize};
