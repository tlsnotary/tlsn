use mpc_core::Block;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum GhashMessage {
    HashKeyPowerShares(HashKeyPowerShares),
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct HashKeyPowerShares(pub Vec<(usize, Block)>);
