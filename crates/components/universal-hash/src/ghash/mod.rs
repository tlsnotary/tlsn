mod ghash_core;
mod ghash_inner;

#[cfg(feature = "ideal")]
pub use ghash_inner::ideal::{ideal_ghash, IdealGhash};
pub use ghash_inner::{Ghash, GhashConfig, GhashConfigBuilder, GhashConfigBuilderError};
