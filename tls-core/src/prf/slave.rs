use super::master::{MasterKe1, MasterKe2, MasterMs1, MasterMs2, MasterMs3};
use super::sha::finalize_sha256_digest;

pub struct Initialized;
pub struct Ms1 {
    /// H(pms xor opad)
    outer_hash_state: [u32; 8],
}

pub struct Ms2 {
    /// H(pms xor opad)
    outer_hash_state: [u32; 8],
}

pub struct Ke1;

pub struct Ke2 {
    /// H(ms xor opad)
    outer_hash_state: [u32; 8],
}

pub struct Cf;

pub trait State {}
impl State for Initialized {}
impl State for Ms1 {}
impl State for Ms2 {}
impl State for Ke1 {}
impl State for Ke2 {}
impl State for Cf {}

pub struct PrfSlave<S>
where
    S: State,
{
    /// State of 2PC PRF Protocol
    state: S,
}

pub struct SlaveMs1 {
    /// H((pms xor opad) || H((pms xor ipad) || seed))
    pub a1: [u8; 32],
}

pub struct SlaveMs2 {
    /// H((pms xor opad) || H((pms xor ipad) || a1))
    pub a2: [u8; 32],
}

pub struct SlaveMs3 {
    /// H((pms xor opad) || H((pms xor ipad) || a2 || seed))
    pub p2: [u8; 32],
}

pub struct SlaveKe1 {
    /// H((ms xor opad) || H((ms xor ipad) || seed))
    pub a1: [u8; 32],
}

pub struct SlaveKe2 {
    /// H((ms xor opad) || H((ms xor ipad) || a1))
    pub a2: [u8; 32],
}

pub struct SlaveCf {}

impl PrfSlave<Initialized> {
    pub fn new() -> Self {
        Self { state: Initialized }
    }

    pub fn next(self, outer_hash_state: [u32; 8], m: MasterMs1) -> (SlaveMs1, PrfSlave<Ms1>) {
        // H((pms xor opad) || H((pms xor ipad) || seed))
        let a1 = finalize_sha256_digest(outer_hash_state.clone(), 64, &m.inner_hash);

        (
            SlaveMs1 { a1 },
            PrfSlave {
                state: Ms1 { outer_hash_state },
            },
        )
    }
}

impl PrfSlave<Ms1> {
    pub fn next(self, m: MasterMs2) -> (SlaveMs2, PrfSlave<Ms2>) {
        // H((pms xor opad) || H((pms xor ipad) || a1))
        let a2 = finalize_sha256_digest(self.state.outer_hash_state.clone(), 64, &m.inner_hash);

        (
            SlaveMs2 { a2 },
            PrfSlave {
                state: Ms2 {
                    outer_hash_state: self.state.outer_hash_state,
                },
            },
        )
    }
}

impl PrfSlave<Ms2> {
    pub fn next(self, m: MasterMs3) -> (SlaveMs3, PrfSlave<Ke1>) {
        // H((pms xor opad) || H((pms xor ipad) || a2 || seed))
        let p2 = finalize_sha256_digest(self.state.outer_hash_state, 64, &m.inner_hash);

        (SlaveMs3 { p2 }, PrfSlave { state: Ke1 })
    }
}

impl PrfSlave<Ke1> {
    pub fn next(self, outer_hash_state: [u32; 8], m: MasterKe1) -> (SlaveKe1, PrfSlave<Ke2>) {
        // H((pms xor opad) || H((pms xor ipad) || seed))
        let a1 = finalize_sha256_digest(outer_hash_state.clone(), 64, &m.inner_hash);

        (
            SlaveKe1 { a1 },
            PrfSlave {
                state: Ke2 { outer_hash_state },
            },
        )
    }
}

impl PrfSlave<Ke2> {
    pub fn next(self, m: MasterKe2) -> (SlaveKe2, PrfSlave<Cf>) {
        // H((pms xor opad) || H((pms xor ipad) || a1))
        let a2 = finalize_sha256_digest(self.state.outer_hash_state.clone(), 64, &m.inner_hash);

        (SlaveKe2 { a2 }, PrfSlave { state: Cf })
    }
}
