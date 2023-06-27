mod ghash_core;
mod ghash_inner;

#[cfg(feature = "mock")]
pub use ghash_inner::mock::*;
pub use ghash_inner::{Ghash, GhashConfig, GhashConfigBuilder, GhashConfigBuilderError};
