use super::sha::finalize_sha256_digest;
use super::HandshakeMessage;
use super::{errors::*, SlaveCore};
use crate::msgs::handshake::*;

#[derive(PartialEq, Copy, Clone, Debug)]
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

#[derive(Debug, Copy, Clone)]
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
        let message = match (self.state, message) {
            (State::MsSetup, HandshakeMessage::MasterMs1(m)) => {
                self.state = State::Ms1;
                HandshakeMessage::SlaveMs1(SlaveMs1 {
                    a1: self.ms1(&m.inner_hash),
                })
            }
            (State::Ms1, HandshakeMessage::MasterMs2(m)) => {
                self.state = State::Ms2;
                HandshakeMessage::SlaveMs2(SlaveMs2 {
                    a2: self.ms2(&m.inner_hash),
                })
            }
            (State::Ms2, HandshakeMessage::MasterMs3(m)) => {
                self.state = State::Ms3;
                HandshakeMessage::SlaveMs3(SlaveMs3 {
                    p2: self.ms3(&m.inner_hash),
                })
            }
            (State::KeSetup, HandshakeMessage::MasterKe1(m)) => {
                self.state = State::Ke1;
                HandshakeMessage::SlaveKe1(SlaveKe1 {
                    a1: self.ke1(&m.inner_hash),
                })
            }
            (State::Ke1, HandshakeMessage::MasterKe2(m)) => {
                self.state = State::Ke2;
                HandshakeMessage::SlaveKe2(SlaveKe2 {
                    a2: self.ke2(&m.inner_hash),
                })
            }
            (State::Ke2, HandshakeMessage::MasterCf1(m)) => {
                self.state = State::Cf1;
                HandshakeMessage::SlaveCf1(SlaveCf1 {
                    a1: self.cf1(&m.inner_hash),
                })
            }
            (State::Cf1, HandshakeMessage::MasterCf2(m)) => {
                self.state = State::Cf2;
                HandshakeMessage::SlaveCf2(SlaveCf2 {
                    verify_data: self.cf2(&m.inner_hash),
                })
            }
            (State::Cf2, HandshakeMessage::MasterSf1(m)) => {
                self.state = State::Sf1;
                HandshakeMessage::SlaveSf1(SlaveSf1 {
                    a1: self.sf1(&m.inner_hash),
                })
            }
            (State::Sf1, HandshakeMessage::MasterSf2(m)) => {
                self.state = State::Sf2;
                HandshakeMessage::SlaveSf2(SlaveSf2 {
                    verify_data: self.sf2(&m.inner_hash),
                })
            }
            _ => {
                return Err(HandshakeError::InvalidMessage(
                    Box::new(self.state),
                    Box::new(message),
                ))
            }
        };
        Ok(message)
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
