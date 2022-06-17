use super::sha::finalize_sha256_digest;
use super::utils::{seed_cf, seed_ke, seed_ms, seed_sf};
use super::HandshakeMessage;
use super::{errors::*, MasterCore};
use crate::msgs::handshake::*;

#[derive(PartialEq, Copy, Clone, Debug)]
enum State {
    Initialized,
    Ms1,
    Ms2,
    Ms3,
    Ke1,
    Ke2,
    KeComplete,
    Cf1,
    Cf2,
    CfComplete,
    Sf1,
    Sf2,
    SfComplete,
}

#[derive(Debug, Copy, Clone)]
pub struct HandshakeMasterCore {
    client_random: [u8; 32],
    server_random: [u8; 32],
    state: State,
    // Depending on the state, the inner hash state will be used for master
    // secret or for key expansion.
    inner_hash_state: Option<[u32; 8]>,
    // Depending on the state, the seed will be used for master secret or for
    // key expansion.
    seed: Option<[u8; 77]>,
    // Depending on the state, seed_fin will be used for Client_Finished or for
    // Server_Finished.
    seed_fin: Option<[u8; 47]>,
    // temp storage for a1 from key expansion
    a1: Option<[u8; 32]>,
    // inner_hash_p1/p2 from key expansion
    inner_hash_p1: Option<[u8; 32]>,
    inner_hash_p2: Option<[u8; 32]>,
    // verify_data for Client_Finished
    client_finished_vd: Option<[u8; 12]>,
    // verify_data for Server_Finished
    server_finished_vd: Option<[u8; 12]>,
}

impl MasterCore for HandshakeMasterCore {
    /// The first method that should be called after instantiation. Performs
    /// setup before we can process master secret related messages.
    fn ms_setup(&mut self, inner_hash_state: [u32; 8]) -> Result<HandshakeMessage, HandshakeError> {
        if self.state != State::Initialized {
            return Err(HandshakeError::WrongState);
        }
        let seed = seed_ms(&self.client_random, &self.server_random);
        // H((pms xor ipad) || seed)
        let inner_hash = finalize_sha256_digest(inner_hash_state, 64, &seed);
        self.seed = Some(seed);
        self.inner_hash_state = Some(inner_hash_state);
        self.state = State::Ms1;
        Ok(HandshakeMessage::MasterMs1(MasterMs1 { inner_hash }))
    }

    // Performs setup before we can process key expansion related messages.
    fn ke_setup(&mut self, inner_hash_state: [u32; 8]) -> Result<HandshakeMessage, HandshakeError> {
        if self.state != State::Ms3 {
            return Err(HandshakeError::WrongState);
        }
        let seed = seed_ke(&self.client_random, &self.server_random);
        // H((ms xor ipad) || seed)
        let inner_hash = finalize_sha256_digest(inner_hash_state, 64, &seed);
        self.seed = Some(seed);
        self.inner_hash_state = Some(inner_hash_state);
        self.state = State::Ke1;
        Ok(HandshakeMessage::MasterKe1(MasterKe1 { inner_hash }))
    }

    // Performs setup before we can process Client_Finished related messages.
    fn cf_setup(&mut self, handshake_blob: &[u8]) -> Result<HandshakeMessage, HandshakeError> {
        if self.state != State::KeComplete {
            return Err(HandshakeError::WrongState);
        }
        let seed = seed_cf(handshake_blob);
        // H((ms xor ipad) || seed)
        let inner_hash = finalize_sha256_digest(self.inner_hash_state.unwrap(), 64, &seed);
        self.seed_fin = Some(seed);
        self.state = State::Cf1;
        Ok(HandshakeMessage::MasterCf1(MasterCf1 { inner_hash }))
    }

    // Performs setup before we can process Server_Finished related messages.
    fn sf_setup(&mut self, handshake_blob: &[u8]) -> Result<HandshakeMessage, HandshakeError> {
        if self.state != State::CfComplete {
            return Err(HandshakeError::WrongState);
        }
        let seed = seed_sf(handshake_blob);
        // H((ms xor ipad) || seed)
        let inner_hash = finalize_sha256_digest(self.inner_hash_state.unwrap(), 64, &seed);
        self.seed_fin = Some(seed);
        self.state = State::Sf1;
        Ok(HandshakeMessage::MasterSf1(MasterSf1 { inner_hash }))
    }

    /// Will be called repeatedly whenever there is a message from Slave that
    /// needs to be processed.
    fn next(
        &mut self,
        message: HandshakeMessage,
    ) -> Result<Option<HandshakeMessage>, HandshakeError> {
        let message = match (self.state, message) {
            (State::Ms1, HandshakeMessage::SlaveMs1(m)) => {
                self.state = State::Ms2;
                Some(HandshakeMessage::MasterMs2(MasterMs2 {
                    inner_hash: self.ms1(&m.a1),
                }))
            }
            (State::Ms2, HandshakeMessage::SlaveMs2(m)) => {
                self.state = State::Ms3;
                Some(HandshakeMessage::MasterMs3(MasterMs3 {
                    inner_hash: self.ms2(&m.a2),
                }))
            }
            (State::Ke1, HandshakeMessage::SlaveKe1(m)) => {
                self.a1 = Some(m.a1);
                self.state = State::Ke2;
                Some(HandshakeMessage::MasterKe2(MasterKe2 {
                    inner_hash: self.ke1(&m.a1),
                }))
            }
            (State::Ke2, HandshakeMessage::SlaveKe2(m)) => {
                let (ihp1, ihp2) = self.ke2(&m.a2);
                self.inner_hash_p1 = Some(ihp1);
                self.inner_hash_p2 = Some(ihp2);
                self.state = State::KeComplete;
                None
            }
            (State::Cf1, HandshakeMessage::SlaveCf1(m)) => {
                self.state = State::Cf2;
                Some(HandshakeMessage::MasterCf2(MasterCf2 {
                    inner_hash: self.cf1(&m.a1),
                }))
            }
            (State::Cf2, HandshakeMessage::SlaveCf2(m)) => {
                self.client_finished_vd = Some(m.verify_data);
                self.state = State::CfComplete;
                None
            }
            (State::Sf1, HandshakeMessage::SlaveSf1(m)) => {
                self.state = State::Sf2;
                Some(HandshakeMessage::MasterSf2(MasterSf2 {
                    inner_hash: self.sf1(&m.a1),
                }))
            }
            (State::Sf2, HandshakeMessage::SlaveSf2(m)) => {
                self.server_finished_vd = Some(m.verify_data);
                self.state = State::SfComplete;
                None
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

    fn get_inner_hashes_ke(self) -> ([u8; 32], [u8; 32]) {
        (self.inner_hash_p1.unwrap(), self.inner_hash_p2.unwrap())
    }

    fn get_client_finished_vd(self) -> [u8; 12] {
        self.client_finished_vd.unwrap()
    }

    fn get_server_finished_vd(self) -> [u8; 12] {
        self.server_finished_vd.unwrap()
    }
}

impl HandshakeMasterCore {
    pub fn new(client_random: [u8; 32], server_random: [u8; 32]) -> Self {
        Self {
            state: State::Initialized,
            client_random,
            server_random,
            inner_hash_state: None,
            seed: None,
            a1: None,
            inner_hash_p1: None,
            inner_hash_p2: None,
            client_finished_vd: None,
            server_finished_vd: None,
            seed_fin: None,
        }
    }
    fn ms1(&mut self, a1: &[u8]) -> [u8; 32] {
        // H((pms xor ipad) || a1)
        finalize_sha256_digest(self.inner_hash_state.unwrap(), 64, a1)
    }

    fn ms2(&mut self, a2: &[u8]) -> [u8; 32] {
        let mut a2_seed = [0u8; 109];
        a2_seed[..32].copy_from_slice(a2);
        a2_seed[32..].copy_from_slice(&self.seed.unwrap());
        // H((pms xor ipad) || a2 || seed)
        finalize_sha256_digest(self.inner_hash_state.unwrap(), 64, &a2_seed)
    }

    fn ke1(&mut self, a1: &[u8]) -> [u8; 32] {
        // H((ms xor ipad) || a1)
        finalize_sha256_digest(self.inner_hash_state.unwrap(), 64, a1)
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

    fn cf1(&mut self, a1: &[u8]) -> [u8; 32] {
        // H((ms xor ipad) || a1 || seed)
        let mut a1_seed = [0u8; 79];
        a1_seed[..32].copy_from_slice(a1);
        a1_seed[32..].copy_from_slice(&self.seed_fin.unwrap());
        finalize_sha256_digest(self.inner_hash_state.unwrap(), 64, &a1_seed)
    }

    fn sf1(&mut self, a1: &[u8]) -> [u8; 32] {
        // H((ms xor ipad) || a1 || seed)
        let mut a1_seed = [0u8; 79];
        a1_seed[..32].copy_from_slice(a1);
        a1_seed[32..].copy_from_slice(&self.seed_fin.unwrap());
        finalize_sha256_digest(self.inner_hash_state.unwrap(), 64, &a1_seed)
    }
}
