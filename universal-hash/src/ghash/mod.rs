mod ghash;
mod ghash_core;

#[cfg(feature = "mock")]
pub use ghash::mock::*;
pub use ghash::{Ghash, GhashConfig, GhashConfigBuilder, GhashConfigBuilderError};
