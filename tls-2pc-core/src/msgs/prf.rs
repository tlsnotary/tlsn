#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum PRFMessage {
    LeaderMs1(LeaderMs1),
    FollowerMs1(FollowerMs1),
    LeaderMs2(LeaderMs2),
    FollowerMs2(FollowerMs2),
    LeaderMs3(LeaderMs3),
    FollowerMs3(FollowerMs3),
    LeaderKe1(LeaderKe1),
    FollowerKe1(FollowerKe1),
    LeaderKe2(LeaderKe2),
    FollowerKe2(FollowerKe2),
    LeaderCf1(LeaderCf1),
    FollowerCf1(FollowerCf1),
    LeaderCf2(LeaderCf2),
    FollowerCf2(FollowerCf2),
    LeaderSf1(LeaderSf1),
    FollowerSf1(FollowerSf1),
    LeaderSf2(LeaderSf2),
    FollowerSf2(FollowerSf2),
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LeaderMs1 {
    /// H((pms xor ipad) || seed)
    pub a1_inner_hash: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LeaderMs2 {
    /// H((pms xor ipad) || a1)
    pub a2_inner_hash: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LeaderMs3 {
    /// H((pms xor ipad) || a2)
    pub p2_inner_hash: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LeaderKe1 {
    /// H((ms xor ipad) || seed)
    pub a1_inner_hash: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LeaderKe2 {
    /// H((ms xor ipad) || a1)
    pub a2_inner_hash: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LeaderCf1 {
    /// H((ms xor ipad) || seed)
    pub a1_inner_hash: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LeaderCf2 {
    /// H((ms xor ipad) || a1 || seed)
    pub p1_inner_hash: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LeaderSf1 {
    /// H((ms xor ipad) || seed)
    pub a1_inner_hash: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LeaderSf2 {
    /// H((ms xor ipad) || a1 || seed)
    pub sf_vd_inner_hash: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FollowerMs1 {
    /// H((pms xor opad) || H((pms xor ipad) || seed))
    pub a1: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FollowerMs2 {
    /// H((pms xor opad) || H((pms xor ipad) || a1))
    pub a2: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FollowerMs3 {
    /// H((pms xor opad) || H((pms xor ipad) || a2 || seed))
    pub p2: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FollowerKe1 {
    /// H((ms xor opad) || H((ms xor ipad) || seed))
    pub a1: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FollowerKe2 {
    /// H((ms xor opad) || H((ms xor ipad) || a1))
    pub a2: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FollowerCf1 {
    /// H((ms xor opad) || H((ms xor ipad) || seed))
    pub a1: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FollowerCf2 {
    pub verify_data: [u8; 12],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FollowerSf1 {
    /// H((ms xor opad) || H((ms xor ipad) || seed))
    pub a1: [u8; 32],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FollowerSf2 {
    pub verify_data: [u8; 12],
}
