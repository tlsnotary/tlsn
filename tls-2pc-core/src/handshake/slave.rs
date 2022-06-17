use super::sha::finalize_sha256_digest;
use super::HandshakeMessage;
use super::{errors::*, SlaveCore};
use crate::msgs::handshake::*;

#[derive(PartialEq, Copy, Clone)]
enum State {
    Initialized,
    MsSetup,
    Ms1,
    Ms2,
    Ms3,
    KeSetup,
    Ke1,
    Ke2,
    Cf1,
    Cf2,
    Sf1,
    Sf2,
}

#[derive(Copy, Clone)]
pub struct HandshakeSlaveCore {
    state: State,
    // Depending on the state, the outer hash state will be used for master
    // secret or for key expansion.
    outer_hash_state: Option<[u32; 8]>,
}

impl SlaveCore for HandshakeSlaveCore {
    /// The first method that should be called after instantiation. Performs
    /// setup before we can process master secret related messages.
    fn ms_setup(&mut self, outer_hash_state: [u32; 8]) -> Result<(), HandshakeError> {
        if self.state != State::Initialized {
            return Err(HandshakeError::WrongState);
        }
        self.outer_hash_state = Some(outer_hash_state);
        self.state = State::MsSetup;
        Ok(())
    }

    // Performs setup before we can process key expansion related messages.
    fn ke_setup(&mut self, outer_hash_state: [u32; 8]) -> Result<(), HandshakeError> {
        if self.state != State::Ms3 {
            return Err(HandshakeError::WrongState);
        }
        self.outer_hash_state = Some(outer_hash_state);
        self.state = State::KeSetup;
        Ok(())
    }

    /// Will be called repeatedly whenever there is a message from Master that
    /// needs to be processed.
    fn next(&mut self, message: HandshakeMessage) -> Result<HandshakeMessage, HandshakeError> {
        match message {
            HandshakeMessage::MasterMs1(m) => {
                if self.state != State::MsSetup {
                    return Err(HandshakeError::WrongState);
                }
                self.state = State::Ms1;
                Ok(HandshakeMessage::SlaveMs1(SlaveMs1 {
                    a1: self.ms1(&m.inner_hash),
                }))
            }
            HandshakeMessage::MasterMs2(m) => {
                if self.state != State::Ms1 {
                    return Err(HandshakeError::OutOfOrder);
                }
                self.state = State::Ms2;
                Ok(HandshakeMessage::SlaveMs2(SlaveMs2 {
                    a2: self.ms2(&m.inner_hash),
                }))
            }
            HandshakeMessage::MasterMs3(m) => {
                if self.state != State::Ms2 {
                    return Err(HandshakeError::OutOfOrder);
                }
                self.state = State::Ms3;
                Ok(HandshakeMessage::SlaveMs3(SlaveMs3 {
                    p2: self.ms3(&m.inner_hash),
                }))
            }
            HandshakeMessage::MasterKe1(m) => {
                if self.state != State::KeSetup {
                    return Err(HandshakeError::WrongState);
                }
                self.state = State::Ke1;
                Ok(HandshakeMessage::SlaveKe1(SlaveKe1 {
                    a1: self.ke1(&m.inner_hash),
                }))
            }
            HandshakeMessage::MasterKe2(m) => {
                if self.state != State::Ke1 {
                    return Err(HandshakeError::OutOfOrder);
                }
                self.state = State::Ke2;
                Ok(HandshakeMessage::SlaveKe2(SlaveKe2 {
                    a2: self.ke2(&m.inner_hash),
                }))
            }
            HandshakeMessage::MasterCf1(m) => {
                if self.state != State::Ke2 {
                    return Err(HandshakeError::OutOfOrder);
                }
                self.state = State::Cf1;
                Ok(HandshakeMessage::SlaveCf1(SlaveCf1 {
                    a1: self.cf1(&m.inner_hash),
                }))
            }
            HandshakeMessage::MasterCf2(m) => {
                if self.state != State::Cf1 {
                    return Err(HandshakeError::OutOfOrder);
                }
                self.state = State::Cf2;
                Ok(HandshakeMessage::SlaveCf2(SlaveCf2 {
                    verify_data: self.cf2(&m.inner_hash),
                }))
            }
            HandshakeMessage::MasterSf1(m) => {
                if self.state != State::Cf2 {
                    return Err(HandshakeError::OutOfOrder);
                }
                self.state = State::Sf1;
                Ok(HandshakeMessage::SlaveSf1(SlaveSf1 {
                    a1: self.sf1(&m.inner_hash),
                }))
            }
            HandshakeMessage::MasterSf2(m) => {
                if self.state != State::Sf1 {
                    return Err(HandshakeError::OutOfOrder);
                }
                self.state = State::Sf2;
                Ok(HandshakeMessage::SlaveSf2(SlaveSf2 {
                    verify_data: self.sf2(&m.inner_hash),
                }))
            }
            _ => Err(HandshakeError::InvalidMessage),
        }
    }
}

impl HandshakeSlaveCore {
    pub fn new() -> Self {
        Self {
            state: State::Initialized,
            outer_hash_state: None,
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
        // H((ms xor opad) || H((ms xor ipad) || seed))
        finalize_sha256_digest(self.outer_hash_state.unwrap(), 64, inner_hash)
    }

    fn ke2(&mut self, inner_hash: &[u8]) -> [u8; 32] {
        // H((ms xor opad) || H((ms xor ipad) || a1))
        finalize_sha256_digest(self.outer_hash_state.unwrap(), 64, inner_hash)
    }

    fn cf1(&mut self, inner_hash: &[u8]) -> [u8; 32] {
        // H((ms xor opad) || H((ms xor ipad) || seed))
        finalize_sha256_digest(self.outer_hash_state.unwrap(), 64, inner_hash)
    }

    fn cf2(&mut self, inner_hash: &[u8]) -> [u8; 12] {
        // H((ms xor opad) || H((ms xor ipad) || a1 || seed))
        let p1 = finalize_sha256_digest(self.outer_hash_state.unwrap(), 64, inner_hash);
        let mut verify_data = [0u8; 12];
        verify_data.copy_from_slice(&p1[..12]);
        verify_data
    }

    fn sf1(&mut self, inner_hash: &[u8]) -> [u8; 32] {
        // H((ms xor opad) || H((ms xor ipad) || seed))
        finalize_sha256_digest(self.outer_hash_state.unwrap(), 64, inner_hash)
    }

    fn sf2(&mut self, inner_hash: &[u8]) -> [u8; 12] {
        // H((ms xor opad) || H((ms xor ipad) || a1 || seed))
        let p1 = finalize_sha256_digest(self.outer_hash_state.unwrap(), 64, inner_hash);
        let mut verify_data = [0u8; 12];
        verify_data.copy_from_slice(&p1[..12]);
        verify_data
    }
}
