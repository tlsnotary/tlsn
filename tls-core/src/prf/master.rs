use super::errors::*;
use super::sha::finalize_sha256_digest;
use super::utils::{seed_ke, seed_ms};
use super::PRFMessage;

#[derive(Copy, Clone)]
pub struct MasterMs1 {
    /// H((pms xor ipad) || seed)
    pub inner_hash: [u8; 32],
}

#[derive(Copy, Clone)]
pub struct MasterMs2 {
    /// H((pms xor ipad) || a1)
    pub inner_hash: [u8; 32],
}

#[derive(Copy, Clone)]
pub struct MasterMs3 {
    /// H((pms xor ipad) || a2)
    pub inner_hash: [u8; 32],
}

#[derive(Copy, Clone)]
pub struct MasterKe1 {
    /// H((ms xor ipad) || seed)
    pub inner_hash: [u8; 32],
}

#[derive(Copy, Clone)]
pub struct MasterKe2 {
    /// H((ms xor ipad) || a1)
    pub inner_hash: [u8; 32],
}

#[derive(Copy, Clone)]
pub struct MasterKe3 {
    /// H((ms xor ipad) || a1 || seed)
    pub inner_hash_p1: [u8; 32],
    /// H((ms xor ipad) || a2 || seed)
    pub inner_hash_p2: [u8; 32],
}

#[derive(std::cmp::PartialEq, Copy, Clone)]
enum State {
    Initialized,
    Ms1,
    Ms2,
    Ms3,
    Ke1,
    Ke2,
    Ke3,
}

#[derive(Copy, Clone)]
pub struct PRFMaster {
    client_random: [u8; 32],
    server_random: [u8; 32],
    state: State,
    // Depending on the state, the inner hash state will be used for master
    // secret or for key expansion.
    inner_hash_state: Option<[u32; 8]>,
    // Depending on the state, the seed will be used for master secret or for
    // key expansion.
    seed: Option<[u8; 77]>,
    // temp storage for a1 from key expansion
    a1: Option<[u8; 32]>,
}

impl PRFMaster {
    pub fn new(client_random: [u8; 32], server_random: [u8; 32]) -> Self {
        Self {
            state: State::Initialized,
            client_random,
            server_random,
            inner_hash_state: None,
            seed: None,
            a1: None,
        }
    }

    /// The first method that should be called after instantiation. Performs
    /// setup before we can process master secret related messages.
    pub fn ms_setup(&mut self, inner_hash_state: [u32; 8]) -> Result<PRFMessage, PRFError> {
        if self.state != State::Initialized {
            return Err(PRFError::WrongState);
        }
        let seed = seed_ms(&self.client_random, &self.server_random);
        // H((pms xor ipad) || seed)
        let inner_hash = finalize_sha256_digest(inner_hash_state, 64, &seed);
        self.seed = Some(seed);
        self.inner_hash_state = Some(inner_hash_state);
        self.state = State::Ms1;
        Ok(PRFMessage::MasterMs1(MasterMs1 { inner_hash }))
    }

    // Performs setup before we can process key expansion related messages.
    pub fn ke_setup(&mut self, inner_hash_state: [u32; 8]) -> Result<PRFMessage, PRFError> {
        if self.state != State::Ms3 {
            return Err(PRFError::WrongState);
        }
        let seed = seed_ke(&self.client_random, &self.server_random);
        // H((ms xor ipad) || seed)
        let inner_hash = finalize_sha256_digest(inner_hash_state, 64, &seed);
        self.seed = Some(seed);
        self.inner_hash_state = Some(inner_hash_state);
        self.state = State::Ke1;
        Ok(PRFMessage::MasterKe1(MasterKe1 { inner_hash }))
    }

    /// Will be called continuously whenever there is a message from Slave that
    /// needs to be processed.
    pub fn next(&mut self, message: PRFMessage) -> Result<PRFMessage, PRFError> {
        match message {
            PRFMessage::SlaveMs1(m) => {
                if self.state != State::Ms1 {
                    return Err(PRFError::OutOfOrder);
                }
                self.state = State::Ms2;
                Ok(PRFMessage::MasterMs2(MasterMs2 {
                    inner_hash: self.ms1(&m.a1),
                }))
            }
            PRFMessage::SlaveMs2(m) => {
                if self.state != State::Ms2 {
                    return Err(PRFError::OutOfOrder);
                }
                self.state = State::Ms3;
                Ok(PRFMessage::MasterMs3(MasterMs3 {
                    inner_hash: self.ms2(&m.a2),
                }))
            }
            PRFMessage::SlaveKe1(m) => {
                if self.state != State::Ke1 {
                    return Err(PRFError::OutOfOrder);
                }
                // H((pms xor ipad) || a1)
                self.a1 = Some(m.a1);
                self.state = State::Ke2;
                Ok(PRFMessage::MasterKe2(MasterKe2 {
                    inner_hash: self.ke1(&m.a1),
                }))
            }
            PRFMessage::SlaveKe2(m) => {
                if self.state != State::Ke2 {
                    return Err(PRFError::OutOfOrder);
                }
                let (inner_hash_p1, inner_hash_p2) = self.ke2(&m.a2);
                self.state = State::Ke3;
                Ok(PRFMessage::MasterKe3(MasterKe3 {
                    inner_hash_p1,
                    inner_hash_p2,
                }))
            }
            _ => Err(PRFError::InvalidMessage),
        }
    }

    fn ms1(&mut self, a1: &[u8]) -> [u8; 32] {
        // H((pms xor ipad) || a1)
        finalize_sha256_digest(self.inner_hash_state.unwrap(), 64, a1)
    }

    fn ms2(&mut self, a2: &[u8]) -> [u8; 32] {
        let mut a2_seed = [0u8; 109];
        a2_seed[..32].copy_from_slice(&a2);
        a2_seed[32..].copy_from_slice(&self.seed.unwrap());
        // H((pms xor ipad) || a2 || seed)
        finalize_sha256_digest(self.inner_hash_state.unwrap(), 64, &a2_seed)
    }

    fn ke1(&mut self, a1: &[u8]) -> [u8; 32] {
        // H((ms xor ipad) || a1)
        finalize_sha256_digest(self.inner_hash_state.unwrap(), 64, &a1)
    }

    fn ke2(&mut self, a2: &[u8]) -> ([u8; 32], [u8; 32]) {
        let mut a1_seed = [0u8; 109];
        a1_seed[..32].copy_from_slice(&self.a1.unwrap());
        a1_seed[32..].copy_from_slice(&self.seed.unwrap());

        let mut a2_seed = [0u8; 109];
        a2_seed[..32].copy_from_slice(a2);
        a2_seed[32..].copy_from_slice(&self.seed.unwrap());

        // H((ms xor ipad) || a1 || seed)
        let inner_hash_p1 = finalize_sha256_digest(self.inner_hash_state.unwrap(), 64, &a1_seed);

        // H((ms xor ipad) || a2 || seed)
        let inner_hash_p2 = finalize_sha256_digest(self.inner_hash_state.unwrap(), 64, &a2_seed);
        (inner_hash_p1, inner_hash_p2)
    }
}
