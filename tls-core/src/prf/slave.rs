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
enum State {
    Initialized,
    MsSetup,
    Ms1,
    Ms2,
    Ms3,
    KeSetup,
    Ke1,
    Ke2,
}

#[derive(Copy, Clone)]
pub struct PRFSlave {
    state: State,
    // Depending on the state, the outer hash state will be used for master
    // secret or for key expansion.
    outer_hash_state: Option<[u32; 8]>,
}

impl PRFSlave {
    pub fn new() -> Self {
        Self {
            state: State::Initialized,
            outer_hash_state: None,
        }
    }

    /// The first method that should be called after instantiation. Performs
    /// setup before we can process master secret related messages.
    pub fn ms_setup(&mut self, outer_hash_state: [u32; 8]) -> Result<(), PRFError> {
        if self.state != State::Initialized {
            return Err(PRFError::WrongState);
        }
        self.outer_hash_state = Some(outer_hash_state);
        self.state = State::MsSetup;
        Ok(())
    }

    // Performs setup before we can process key expansion related messages.
    pub fn ke_setup(&mut self, outer_hash_state: [u32; 8]) -> Result<(), PRFError> {
        if self.state != State::Ms3 {
            return Err(PRFError::WrongState);
        }
        self.outer_hash_state = Some(outer_hash_state);
        self.state = State::KeSetup;
        Ok(())
    }

    pub fn next(&mut self, message: PRFMessage) -> Result<PRFMessage, PRFError> {
        match message {
            PRFMessage::MasterMs1(m) => {
                if self.state != State::MsSetup {
                    return Err(PRFError::WrongState);
                }
                self.state = State::Ms1;
                Ok(PRFMessage::SlaveMs1(SlaveMs1 {
                    a1: self.ms1(&m.inner_hash),
                }))
            }
            PRFMessage::MasterMs2(m) => {
                if self.state != State::Ms1 {
                    return Err(PRFError::OutOfOrder);
                }
                self.state = State::Ms2;
                Ok(PRFMessage::SlaveMs2(SlaveMs2 {
                    a2: self.ms2(&m.inner_hash),
                }))
            }
            PRFMessage::MasterMs3(m) => {
                if self.state != State::Ms2 {
                    return Err(PRFError::OutOfOrder);
                }
                self.state = State::Ms3;
                Ok(PRFMessage::SlaveMs3(SlaveMs3 {
                    p2: self.ms3(&m.inner_hash),
                }))
            }
            PRFMessage::MasterKe1(m) => {
                if self.state != State::KeSetup {
                    return Err(PRFError::WrongState);
                }
                self.state = State::Ke1;
                Ok(PRFMessage::SlaveKe1(SlaveKe1 {
                    a1: self.ke1(&m.inner_hash),
                }))
            }
            PRFMessage::MasterKe2(m) => {
                if self.state != State::Ke1 {
                    return Err(PRFError::OutOfOrder);
                }
                self.state = State::Ke2;
                Ok(PRFMessage::SlaveKe2(SlaveKe2 {
                    a2: self.ke2(&m.inner_hash),
                }))
            }
            _ => Err(PRFError::InvalidMessage),
        }
    }

    fn ms1(&mut self, inner_hash: &[u8]) -> [u8; 32] {
        // H((pms xor opad) || H((pms xor ipad) || seed))
        finalize_sha256_digest(self.outer_hash_state.unwrap(), 64, inner_hash)
    }

    fn ms2(&mut self, inner_hash: &[u8]) -> [u8; 32] {
        // H((pms xor opad) || H((pms xor ipad) || a1))
        finalize_sha256_digest(self.outer_hash_state.unwrap(), 64, inner_hash)
    }

    fn ms3(&mut self, inner_hash: &[u8]) -> [u8; 32] {
        // H((pms xor opad) || H((pms xor ipad) || a2 || seed))
        finalize_sha256_digest(self.outer_hash_state.unwrap(), 64, inner_hash)
    }

    fn ke1(&mut self, inner_hash: &[u8]) -> [u8; 32] {
        // H((pms xor opad) || H((pms xor ipad) || seed))
        finalize_sha256_digest(self.outer_hash_state.unwrap(), 64, inner_hash)
    }

    fn ke2(&mut self, inner_hash: &[u8]) -> [u8; 32] {
        // H((pms xor opad) || H((pms xor ipad) || a1))
        finalize_sha256_digest(self.outer_hash_state.unwrap(), 64, inner_hash)
    }
}
