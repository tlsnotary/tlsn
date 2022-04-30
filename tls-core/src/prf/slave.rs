use super::errors::*;
use super::sha::finalize_sha256_digest;
use super::PRFMessage;

#[derive(Copy, Clone)]
pub struct SlaveMs1 {
    /// H((pms xor opad) || H((pms xor ipad) || seed))
    pub a1: [u8; 32],
}

#[derive(Copy, Clone)]
pub struct SlaveMs2 {
    /// H((pms xor opad) || H((pms xor ipad) || a1))
    pub a2: [u8; 32],
}

#[derive(Copy, Clone)]
pub struct SlaveMs3 {
    /// H((pms xor opad) || H((pms xor ipad) || a2 || seed))
    pub p2: [u8; 32],
}

#[derive(Copy, Clone)]
pub struct SlaveKe1 {
    /// H((ms xor opad) || H((ms xor ipad) || seed))
    pub a1: [u8; 32],
}

#[derive(Copy, Clone)]
pub struct SlaveKe2 {
    /// H((ms xor opad) || H((ms xor ipad) || a1))
    pub a2: [u8; 32],
}

#[derive(std::cmp::PartialEq, Copy, Clone)]
pub enum PRFSlaveState {
    Initialized,
    SlaveMs1Sent,
    SlaveMs2Sent,
    SlaveMs3Sent,
    SlaveKe1Sent,
    SlaveKe2Sent,
}

#[derive(Copy, Clone)]
pub struct PrfSlave {
    state: PRFSlaveState,
    // Depending on the state, the outer hash state will be used for master
    // secret or for key expansion.
    outer_hash_state: Option<[u32; 8]>,
}

impl PrfSlave {
    pub fn new() -> Self {
        Self {
            state: PRFSlaveState::Initialized,
            outer_hash_state: None,
        }
    }

    pub fn next(
        &mut self,
        message: PRFMessage,
        outer_hash_state: Option<[u32; 8]>,
    ) -> Result<PRFMessage, PRFError> {
        match message {
            PRFMessage::MasterMs1(m) => {
                if self.state != PRFSlaveState::Initialized {
                    return Err(PRFError::OutOfOrder);
                }
                // H((pms xor opad) || H((pms xor ipad) || seed))
                let a1 = finalize_sha256_digest(outer_hash_state.unwrap(), 64, &m.inner_hash);
                self.outer_hash_state = Some(outer_hash_state.unwrap());
                self.state = PRFSlaveState::SlaveMs1Sent;
                Ok(PRFMessage::SlaveMs1(SlaveMs1 { a1 }))
            }
            PRFMessage::MasterMs2(m) => {
                if self.state != PRFSlaveState::SlaveMs1Sent {
                    return Err(PRFError::OutOfOrder);
                }
                // H((pms xor opad) || H((pms xor ipad) || a1))
                let a2 = finalize_sha256_digest(self.outer_hash_state.unwrap(), 64, &m.inner_hash);
                self.state = PRFSlaveState::SlaveMs2Sent;
                Ok(PRFMessage::SlaveMs2(SlaveMs2 { a2 }))
            }
            PRFMessage::MasterMs3(m) => {
                if self.state != PRFSlaveState::SlaveMs2Sent {
                    return Err(PRFError::OutOfOrder);
                }
                // H((pms xor opad) || H((pms xor ipad) || a2 || seed))
                let p2 = finalize_sha256_digest(self.outer_hash_state.unwrap(), 64, &m.inner_hash);
                self.state = PRFSlaveState::SlaveMs3Sent;
                Ok(PRFMessage::SlaveMs3(SlaveMs3 { p2 }))
            }
            PRFMessage::MasterKe1(m) => {
                if self.state != PRFSlaveState::SlaveMs3Sent {
                    return Err(PRFError::OutOfOrder);
                }
                // H((pms xor opad) || H((pms xor ipad) || seed))
                let a1 = finalize_sha256_digest(outer_hash_state.unwrap(), 64, &m.inner_hash);
                self.outer_hash_state = outer_hash_state;
                self.state = PRFSlaveState::SlaveKe1Sent;
                Ok(PRFMessage::SlaveKe1(SlaveKe1 { a1 }))
            }
            PRFMessage::MasterKe2(m) => {
                if self.state != PRFSlaveState::SlaveKe1Sent {
                    return Err(PRFError::OutOfOrder);
                }
                // H((pms xor opad) || H((pms xor ipad) || a1))
                let a2 = finalize_sha256_digest(self.outer_hash_state.unwrap(), 64, &m.inner_hash);
                self.state = PRFSlaveState::SlaveKe2Sent;
                Ok(PRFMessage::SlaveKe2(SlaveKe2 { a2 }))
            }
            _ => Err(PRFError::InvalidMessage),
        }
    }
}
