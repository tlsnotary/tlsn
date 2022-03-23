use super::sha::finalize_sha256_digest;
use super::slave::{SlaveMs1, SlaveMs2};

pub struct Initialized;
pub struct Ms1 {
    /// master secret || client_random || server_random
    seed: [u8; 77],
    /// H(pms xor ipad)
    inner_hash_state: [u32; 8],
}

pub struct Ms2 {
    /// master secret || client_random || server_random
    seed: [u8; 77],
    /// H(pms xor ipad)
    inner_hash_state: [u32; 8],
}
pub struct Ke1;

pub trait State {}
impl State for Initialized {}
impl State for Ms1 {}
impl State for Ms2 {}
impl State for Ke1 {}

pub struct PrfMaster<S>
where
    S: State,
{
    /// State of 2PC PRF Protocol
    state: S,
    client_random: [u8; 32],
    server_random: [u8; 32],
}

pub struct MasterMs1 {
    /// H((pms xor ipad) || seed)
    pub inner_hash: [u8; 32],
}

pub struct MasterMs2 {
    /// H((pms xor ipad) || a1)
    pub inner_hash: [u8; 32],
}

pub struct MasterMs3 {
    /// H((pms xor ipad) || a2)
    pub inner_hash: [u8; 32],
}

pub struct MasterKe1 {
    /// H((pms xor ipad) || a2 || seed)
    pub inner_hash: [u8; 32],
}

impl PrfMaster<Initialized> {
    pub fn new(client_random: [u8; 32], server_random: [u8; 32]) -> Self {
        Self {
            state: Initialized,
            client_random,
            server_random,
        }
    }

    pub fn next(self, inner_hash_state: [u32; 8]) -> (MasterMs1, PrfMaster<Ms1>) {
        let mut seed = [0u8; 77];
        seed[..13].copy_from_slice(b"master secret");
        seed[13..45].copy_from_slice(&self.client_random);
        seed[45..].copy_from_slice(&self.server_random);
        // H((pms xor ipad) || a0)
        let inner_hash = finalize_sha256_digest(inner_hash_state.clone(), 64, &seed);

        (
            MasterMs1 { inner_hash },
            PrfMaster {
                state: Ms1 {
                    seed,
                    inner_hash_state,
                },
                client_random: self.client_random,
                server_random: self.server_random,
            },
        )
    }
}

impl PrfMaster<Ms1> {
    pub fn next(self, m: SlaveMs1) -> (MasterMs2, PrfMaster<Ms2>) {
        // H((pms xor ipad) || a1)
        let inner_hash = finalize_sha256_digest(self.state.inner_hash_state.clone(), 64, &m.a1);

        (
            MasterMs2 { inner_hash },
            PrfMaster {
                state: Ms2 {
                    seed: self.state.seed,
                    inner_hash_state: self.state.inner_hash_state,
                },
                client_random: self.client_random,
                server_random: self.server_random,
            },
        )
    }
}

impl PrfMaster<Ms2> {
    pub fn next(self, m: SlaveMs2) -> (MasterMs3, PrfMaster<Ke1>) {
        let mut a2_seed = [0u8; 109];
        a2_seed[..32].copy_from_slice(&m.a2);
        a2_seed[32..].copy_from_slice(&self.state.seed);
        // H((pms xor ipad) || a2 || seed)
        let inner_hash = finalize_sha256_digest(self.state.inner_hash_state, 64, &a2_seed);

        (
            MasterMs3 { inner_hash },
            PrfMaster {
                state: Ke1,
                client_random: self.client_random,
                server_random: self.server_random,
            },
        )
    }
}

impl PrfMaster<Ke1> {}
