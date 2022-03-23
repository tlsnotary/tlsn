use super::sha::finalize_sha256_digest;
use super::slave::{SlaveKe1, SlaveKe2, SlaveMs1, SlaveMs2};

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

pub struct Ke2 {
    /// key expansion || client_random || server_random
    seed: [u8; 77],
    /// H(ms xor ipad)
    inner_hash_state: [u32; 8],
}

pub struct Ke3 {
    /// key expansion || client_random || server_random
    seed: [u8; 77],
    /// H(ms xor ipad)
    inner_hash_state: [u32; 8],
    /// H((ms xor opad) || H((ms xor ipad) || seed))
    a1: [u8; 32],
}

pub struct Cf;

pub trait State {}
impl State for Initialized {}
impl State for Ms1 {}
impl State for Ms2 {}
impl State for Ke1 {}
impl State for Ke2 {}
impl State for Ke3 {}
impl State for Cf {}

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
    /// H((ms xor ipad) || seed)
    pub inner_hash: [u8; 32],
}

pub struct MasterKe2 {
    /// H((ms xor ipad) || a1)
    pub inner_hash: [u8; 32],
}

pub struct MasterKe3 {
    /// H((ms xor ipad) || a1 || seed)
    pub inner_hash_p1: [u8; 32],
    /// H((ms xor ipad) || a2 || seed)
    pub inner_hash_p2: [u8; 32],
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
        // H((pms xor ipad) || seed)
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

impl PrfMaster<Ke1> {
    pub fn next(self, inner_hash_state: [u32; 8]) -> (MasterKe1, PrfMaster<Ke2>) {
        let mut seed = [0u8; 77];
        seed[..13].copy_from_slice(b"key expansion");
        seed[13..45].copy_from_slice(&self.server_random);
        seed[45..].copy_from_slice(&self.client_random);
        // H((ms xor ipad) || seed)
        let inner_hash = finalize_sha256_digest(inner_hash_state.clone(), 64, &seed);

        (
            MasterKe1 { inner_hash },
            PrfMaster {
                state: Ke2 {
                    seed,
                    inner_hash_state,
                },
                client_random: self.client_random,
                server_random: self.server_random,
            },
        )
    }
}

impl PrfMaster<Ke2> {
    pub fn next(self, m: SlaveKe1) -> (MasterKe2, PrfMaster<Ke3>) {
        // H((pms xor ipad) || a1)
        let inner_hash = finalize_sha256_digest(self.state.inner_hash_state.clone(), 64, &m.a1);

        (
            MasterKe2 { inner_hash },
            PrfMaster {
                state: Ke3 {
                    a1: m.a1,
                    seed: self.state.seed,
                    inner_hash_state: self.state.inner_hash_state,
                },
                client_random: self.client_random,
                server_random: self.server_random,
            },
        )
    }
}

impl PrfMaster<Ke3> {
    pub fn next(self, m: SlaveKe2) -> (MasterKe3, PrfMaster<Cf>) {
        let mut a1_seed = [0u8; 109];
        a1_seed[..32].copy_from_slice(&self.state.a1);
        a1_seed[32..].copy_from_slice(&self.state.seed);

        let mut a2_seed = [0u8; 109];
        a2_seed[..32].copy_from_slice(&m.a2);
        a2_seed[32..].copy_from_slice(&self.state.seed);

        // H((pms xor ipad) || a1 || seed)
        let inner_hash_p1 =
            finalize_sha256_digest(self.state.inner_hash_state.clone(), 64, &a1_seed);

        // H((pms xor ipad) || a2 || seed)
        let inner_hash_p2 = finalize_sha256_digest(self.state.inner_hash_state, 64, &a2_seed);

        (
            MasterKe3 {
                inner_hash_p1,
                inner_hash_p2,
            },
            PrfMaster {
                state: Cf,
                client_random: self.client_random,
                server_random: self.server_random,
            },
        )
    }
}
