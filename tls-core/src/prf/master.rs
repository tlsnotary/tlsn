use super::errors::*;
use super::sha::finalize_sha256_digest;
use super::utils::{seed_ke, seed_ms};
use super::PRFMessage;

#[derive(Copy, Clone)]
pub struct MasterSetup {
    pub inner_hash_state: [u32; 8],
}

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
pub struct KeInit {
    pub inner_hash_state: [u32; 8],
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
pub enum PRFMasterState {
    Initialized,
    MasterMs1Sent,
    MasterMs2Sent,
    MasterMs3Sent,
    MasterKe1Sent,
    MasterKe2Sent,
    MasterKe3Sent,
}

#[derive(Copy, Clone)]
pub struct PrfMaster {
    client_random: [u8; 32],
    server_random: [u8; 32],
    state: PRFMasterState,
    // Depending on the state, the inner hash state will be used for master
    // secret or for key expansion.
    inner_hash_state: Option<[u32; 8]>,
    // Depending on the state, the seed will be used for master secret or for
    // key expansion.
    seed: Option<[u8; 77]>,
    // temp storage for a1 from key expansion
    a1: Option<[u8; 32]>,
}

impl PrfMaster {
    pub fn new(client_random: [u8; 32], server_random: [u8; 32]) -> Self {
        Self {
            state: PRFMasterState::Initialized,
            client_random,
            server_random,
            inner_hash_state: None,
            seed: None,
            a1: None,
        }
    }

    pub fn next(&mut self, message: PRFMessage) -> Result<PRFMessage, PRFError> {
        match message {
            PRFMessage::MasterSetup(m) => {
                if self.state != PRFMasterState::Initialized {
                    return Err(PRFError::OutOfOrder);
                }
                let seed = seed_ms(&self.client_random, &self.server_random);
                // H((pms xor ipad) || seed)
                let inner_hash = finalize_sha256_digest(m.inner_hash_state, 64, &seed);
                self.seed = Some(seed);
                self.inner_hash_state = Some(m.inner_hash_state);
                self.state = PRFMasterState::MasterMs1Sent;
                Ok(PRFMessage::MasterMs1(MasterMs1 { inner_hash }))
            }
            PRFMessage::SlaveMs1(m) => {
                if self.state != PRFMasterState::MasterMs1Sent {
                    return Err(PRFError::OutOfOrder);
                }
                // H((pms xor ipad) || a1)
                let inner_hash = finalize_sha256_digest(self.inner_hash_state.unwrap(), 64, &m.a1);
                self.state = PRFMasterState::MasterMs2Sent;
                Ok(PRFMessage::MasterMs2(MasterMs2 { inner_hash }))
            }
            PRFMessage::SlaveMs2(m) => {
                if self.state != PRFMasterState::MasterMs2Sent {
                    return Err(PRFError::OutOfOrder);
                }
                let mut a2_seed = [0u8; 109];
                a2_seed[..32].copy_from_slice(&m.a2);
                a2_seed[32..].copy_from_slice(&self.seed.unwrap());
                // H((pms xor ipad) || a2 || seed)
                let inner_hash =
                    finalize_sha256_digest(self.inner_hash_state.unwrap(), 64, &a2_seed);
                self.state = PRFMasterState::MasterMs3Sent;
                Ok(PRFMessage::MasterMs3(MasterMs3 { inner_hash }))
            }
            PRFMessage::KeInit(m) => {
                if self.state != PRFMasterState::MasterMs3Sent {
                    return Err(PRFError::OutOfOrder);
                }
                let seed = seed_ke(&self.client_random, &self.server_random);
                // H((ms xor ipad) || seed)
                let inner_hash = finalize_sha256_digest(m.inner_hash_state, 64, &seed);
                self.seed = Some(seed);
                self.inner_hash_state = Some(m.inner_hash_state);
                self.state = PRFMasterState::MasterKe1Sent;
                Ok(PRFMessage::MasterKe1(MasterKe1 { inner_hash }))
            }
            PRFMessage::SlaveKe1(m) => {
                if self.state != PRFMasterState::MasterKe1Sent {
                    return Err(PRFError::OutOfOrder);
                }
                // H((pms xor ipad) || a1)
                let inner_hash = finalize_sha256_digest(self.inner_hash_state.unwrap(), 64, &m.a1);
                self.a1 = Some(m.a1);
                self.state = PRFMasterState::MasterKe2Sent;
                Ok(PRFMessage::MasterKe2(MasterKe2 { inner_hash }))
            }
            PRFMessage::SlaveKe2(m) => {
                if self.state != PRFMasterState::MasterKe2Sent {
                    return Err(PRFError::OutOfOrder);
                }
                let mut a1_seed = [0u8; 109];
                a1_seed[..32].copy_from_slice(&self.a1.unwrap());
                a1_seed[32..].copy_from_slice(&self.seed.unwrap());

                let mut a2_seed = [0u8; 109];
                a2_seed[..32].copy_from_slice(&m.a2);
                a2_seed[32..].copy_from_slice(&self.seed.unwrap());

                // H((pms xor ipad) || a1 || seed)
                let inner_hash_p1 =
                    finalize_sha256_digest(self.inner_hash_state.unwrap(), 64, &a1_seed);

                // H((pms xor ipad) || a2 || seed)
                let inner_hash_p2 =
                    finalize_sha256_digest(self.inner_hash_state.unwrap(), 64, &a2_seed);

                self.state = PRFMasterState::MasterKe3Sent;
                Ok(PRFMessage::MasterKe3(MasterKe3 {
                    inner_hash_p1,
                    inner_hash_p2,
                }))
            }
            _ => Err(PRFError::InvalidMessage),
        }
    }
}
