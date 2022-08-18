#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum HandshakeMessage {
    MasterMs1(MasterMs1),
    SlaveMs1(SlaveMs1),
    MasterMs2(MasterMs2),
    SlaveMs2(SlaveMs2),
    MasterMs3(MasterMs3),
    SlaveMs3(SlaveMs3),
    MasterKe1(MasterKe1),
    SlaveKe1(SlaveKe1),
    MasterKe2(MasterKe2),
    SlaveKe2(SlaveKe2),
    MasterCf1(MasterCf1),
    SlaveCf1(SlaveCf1),
    MasterCf2(MasterCf2),
    SlaveCf2(SlaveCf2),
    MasterSf1(MasterSf1),
    SlaveSf1(SlaveSf1),
    MasterSf2(MasterSf2),
    SlaveSf2(SlaveSf2),
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MasterMs1 {
    /// H((pms xor ipad) || seed)
    pub inner_hash: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MasterMs2 {
    /// H((pms xor ipad) || a1)
    pub inner_hash: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MasterMs3 {
    /// H((pms xor ipad) || a2)
    pub inner_hash: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MasterKe1 {
    /// H((ms xor ipad) || seed)
    pub inner_hash: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MasterKe2 {
    /// H((ms xor ipad) || a1)
    pub inner_hash: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MasterCf1 {
    /// H((ms xor ipad) || seed)
    pub inner_hash: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MasterCf2 {
    /// H((ms xor ipad) || a1 || seed)
    pub inner_hash: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MasterSf1 {
    /// H((ms xor ipad) || seed)
    pub inner_hash: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MasterSf2 {
    /// H((ms xor ipad) || a1 || seed)
    pub inner_hash: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SlaveMs1 {
    /// H((pms xor opad) || H((pms xor ipad) || seed))
    pub a1: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SlaveMs2 {
    /// H((pms xor opad) || H((pms xor ipad) || a1))
    pub a2: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SlaveMs3 {
    /// H((pms xor opad) || H((pms xor ipad) || a2 || seed))
    pub p2: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SlaveKe1 {
    /// H((ms xor opad) || H((ms xor ipad) || seed))
    pub a1: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SlaveKe2 {
    /// H((ms xor opad) || H((ms xor ipad) || a1))
    pub a2: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SlaveCf1 {
    /// H((ms xor opad) || H((ms xor ipad) || seed))
    pub a1: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SlaveCf2 {
    pub verify_data: [u8; 12],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SlaveSf1 {
    /// H((ms xor opad) || H((ms xor ipad) || seed))
    pub a1: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SlaveSf2 {
    pub verify_data: [u8; 12],
}
