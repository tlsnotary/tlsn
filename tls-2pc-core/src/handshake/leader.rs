use super::{
    sha::finalize_sha256_digest,
    utils::{seed_cf, seed_ke, seed_ms, seed_sf},
};
use crate::msgs::handshake as msgs;

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Ms1 {}
    impl Sealed for super::Ms2 {}
    impl Sealed for super::Ms3 {}
    impl Sealed for super::Ke1 {}
    impl Sealed for super::Ke2 {}
    impl Sealed for super::Ke3 {}
    impl Sealed for super::Cf1 {}
    impl Sealed for super::Cf2 {}
    impl Sealed for super::Cf3 {}
    impl Sealed for super::Sf1 {}
    impl Sealed for super::Sf2 {}
    impl Sealed for super::Sf3 {}
}

pub trait State: sealed::Sealed {}

pub struct Ms1 {
    inner_hash_state: [u32; 8],
}
pub struct Ms2 {
    seed_ms: [u8; 77],
    inner_hash_state: [u32; 8],
}
pub struct Ms3 {
    seed_ms: [u8; 77],
    inner_hash_state: [u32; 8],
}
pub struct Ke1 {}
pub struct Ke2 {
    seed_ke: [u8; 77],
    inner_hash_state: [u32; 8],
}
pub struct Ke3 {
    seed_ke: [u8; 77],
    inner_hash_state: [u32; 8],
    a1: [u8; 32],
}
pub struct Cf1 {
    inner_hash_state: [u32; 8],
}
pub struct Cf2 {
    seed_cf: [u8; 47],
    inner_hash_state: [u32; 8],
}
pub struct Cf3 {
    inner_hash_state: [u32; 8],
}
pub struct Sf1 {
    inner_hash_state: [u32; 8],
}
pub struct Sf2 {
    inner_hash_state: [u32; 8],
    seed_sf: [u8; 47],
}
pub struct Sf3 {}

impl State for Ms1 {}
impl State for Ms2 {}
impl State for Ms3 {}
impl State for Ke1 {}
impl State for Ke2 {}
impl State for Ke3 {}
impl State for Cf1 {}
impl State for Cf2 {}
impl State for Cf3 {}
impl State for Sf1 {}
impl State for Sf2 {}
impl State for Sf3 {}

pub struct HandshakeLeader<S: State> {
    state: S,
    client_random: [u8; 32],
    server_random: [u8; 32],
}

impl HandshakeLeader<Ms1> {
    pub fn new(
        client_random: [u8; 32],
        server_random: [u8; 32],
        inner_hash_state: [u32; 8],
    ) -> HandshakeLeader<Ms1> {
        HandshakeLeader {
            state: Ms1 { inner_hash_state },
            client_random,
            server_random,
        }
    }

    /// H((pms xor ipad) || seed)
    pub fn next(self) -> (msgs::LeaderMs1, HandshakeLeader<Ms2>) {
        let seed_ms = seed_ms(&self.client_random, &self.server_random);
        let inner_hash = finalize_sha256_digest(self.state.inner_hash_state, 64, &seed_ms);
        (
            msgs::LeaderMs1 { inner_hash },
            HandshakeLeader {
                state: Ms2 {
                    seed_ms,
                    inner_hash_state: self.state.inner_hash_state,
                },
                client_random: self.client_random,
                server_random: self.server_random,
            },
        )
    }
}

impl HandshakeLeader<Ms2> {
    /// H((pms xor ipad) || a1)
    pub fn next(self, msg: msgs::FollowerMs1) -> (msgs::LeaderMs2, HandshakeLeader<Ms3>) {
        let inner_hash = finalize_sha256_digest(self.state.inner_hash_state, 64, &msg.a1);
        (
            msgs::LeaderMs2 { inner_hash },
            HandshakeLeader {
                state: Ms3 {
                    seed_ms: self.state.seed_ms,
                    inner_hash_state: self.state.inner_hash_state,
                },
                client_random: self.client_random,
                server_random: self.server_random,
            },
        )
    }
}

impl HandshakeLeader<Ms3> {
    pub fn next(self, msg: msgs::FollowerMs2) -> (msgs::LeaderMs3, HandshakeLeader<Ke1>) {
        let mut a2_seed = [0u8; 109];
        a2_seed[..32].copy_from_slice(&msg.a2);
        a2_seed[32..].copy_from_slice(&self.state.seed_ms);
        // H((pms xor ipad) || a2 || seed)
        let inner_hash = finalize_sha256_digest(self.state.inner_hash_state, 64, &a2_seed);
        (
            msgs::LeaderMs3 { inner_hash },
            HandshakeLeader {
                state: Ke1 {},
                client_random: self.client_random,
                server_random: self.server_random,
            },
        )
    }
}

impl HandshakeLeader<Ke1> {
    /// H((ms xor ipad) || seed)
    pub fn next(self, inner_hash_state: [u32; 8]) -> (msgs::LeaderKe1, HandshakeLeader<Ke2>) {
        let seed_ke = seed_ke(&self.client_random, &self.server_random);
        let inner_hash = finalize_sha256_digest(inner_hash_state, 64, &seed_ke);
        (
            msgs::LeaderKe1 { inner_hash },
            HandshakeLeader {
                state: Ke2 {
                    seed_ke,
                    inner_hash_state,
                },
                client_random: self.client_random,
                server_random: self.server_random,
            },
        )
    }
}

impl HandshakeLeader<Ke2> {
    /// H((ms xor ipad) || a1)
    pub fn next(self, msg: msgs::FollowerKe2) -> (msgs::LeaderKe2, HandshakeLeader<Ke3>) {
        let inner_hash = finalize_sha256_digest(self.state.inner_hash_state, 64, &msg.a1);
        (
            msgs::LeaderKe2 { inner_hash },
            HandshakeLeader {
                state: Ke3 {
                    seed_ke: self.state.seed_ke,
                    inner_hash_state: self.state.inner_hash_state,
                    a1: msg.a1,
                },
                client_random: self.client_random,
                server_random: self.server_random,
            },
        )
    }
}

impl HandshakeLeader<Ke3> {
    pub fn next(self, msg: msgs::FollowerKe3) -> (([u8; 32], [u8; 32]), HandshakeLeader<Cf1>) {
        let mut a1_seed = [0u8; 109];
        a1_seed[..32].copy_from_slice(&self.state.a1);
        a1_seed[32..].copy_from_slice(&self.state.seed_ke);

        let mut a2_seed = [0u8; 109];
        a2_seed[..32].copy_from_slice(&msg.a2);
        a2_seed[32..].copy_from_slice(&self.state.seed_ke);

        // H((ms xor ipad) || a1 || seed)
        let inner_hash_p1 = finalize_sha256_digest(self.state.inner_hash_state, 64, &a1_seed);
        // H((ms xor ipad) || a2 || seed)
        let inner_hash_p2 = finalize_sha256_digest(self.state.inner_hash_state, 64, &a2_seed);
        (
            (inner_hash_p1, inner_hash_p2),
            HandshakeLeader {
                state: Cf1 {
                    inner_hash_state: self.state.inner_hash_state,
                },
                client_random: self.client_random,
                server_random: self.server_random,
            },
        )
    }
}

impl HandshakeLeader<Cf1> {
    /// H((ms xor ipad) || seed)
    pub fn next(self, handshake_blob: &[u8]) -> (msgs::LeaderCf1, HandshakeLeader<Cf2>) {
        let seed_cf = seed_cf(handshake_blob);
        let inner_hash = finalize_sha256_digest(self.state.inner_hash_state, 64, &seed_cf);
        (
            msgs::LeaderCf1 { inner_hash },
            HandshakeLeader {
                state: Cf2 {
                    seed_cf,
                    inner_hash_state: self.state.inner_hash_state,
                },
                client_random: self.client_random,
                server_random: self.server_random,
            },
        )
    }
}

impl HandshakeLeader<Cf2> {
    /// H((ms xor ipad) || a1 || seed)
    pub fn next(self, msg: msgs::FollowerCf1) -> (msgs::LeaderCf2, HandshakeLeader<Cf3>) {
        let mut a1_seed = [0u8; 79];
        a1_seed[..32].copy_from_slice(&msg.a1);
        a1_seed[32..].copy_from_slice(&self.state.seed_cf);
        let inner_hash = finalize_sha256_digest(self.state.inner_hash_state, 64, &a1_seed);
        (
            msgs::LeaderCf2 { inner_hash },
            HandshakeLeader {
                state: Cf3 {
                    inner_hash_state: self.state.inner_hash_state,
                },
                client_random: self.client_random,
                server_random: self.server_random,
            },
        )
    }
}

impl HandshakeLeader<Cf3> {
    pub fn next(self, msg: msgs::FollowerCf2) -> ([u8; 12], HandshakeLeader<Sf1>) {
        (
            msg.verify_data,
            HandshakeLeader {
                state: Sf1 {
                    inner_hash_state: self.state.inner_hash_state,
                },
                client_random: self.client_random,
                server_random: self.server_random,
            },
        )
    }
}

impl HandshakeLeader<Sf1> {
    pub fn next(self, handshake_blob: &[u8]) -> (msgs::LeaderSf1, HandshakeLeader<Sf2>) {
        let seed_sf = seed_sf(handshake_blob);
        let inner_hash = finalize_sha256_digest(self.state.inner_hash_state, 64, &seed_sf);
        (
            msgs::LeaderSf1 { inner_hash },
            HandshakeLeader {
                state: Sf2 {
                    seed_sf,
                    inner_hash_state: self.state.inner_hash_state,
                },
                client_random: self.client_random,
                server_random: self.server_random,
            },
        )
    }
}

impl HandshakeLeader<Sf2> {
    /// H((ms xor ipad) || a1 || seed)
    pub fn next(self, msg: msgs::FollowerSf1) -> (msgs::LeaderSf2, HandshakeLeader<Sf3>) {
        let mut a1_seed = [0u8; 79];
        a1_seed[..32].copy_from_slice(&msg.a1);
        a1_seed[32..].copy_from_slice(&self.state.seed_sf);
        let inner_hash = finalize_sha256_digest(self.state.inner_hash_state, 64, &a1_seed);
        (
            msgs::LeaderSf2 { inner_hash },
            HandshakeLeader {
                state: Sf3 {},
                client_random: self.client_random,
                server_random: self.server_random,
            },
        )
    }
}

impl HandshakeLeader<Sf3> {
    pub fn next(self, msg: msgs::FollowerSf2) -> [u8; 12] {
        msg.verify_data
    }
}

// #[derive(Copy, Clone)]
// pub struct HandshakeMaster {
//     client_random: [u8; 32],
//     server_random: [u8; 32],
//     state: State,
//     // Depending on the state, the inner hash state will be used for master
//     // secret or for key expansion.
//     inner_hash_state: Option<[u32; 8]>,
//     // Depending on the state, the seed will be used for master secret or for
//     // key expansion.
//     seed: Option<[u8; 77]>,
//     // Depending on the state, seed_fin will be used for Client_Finished or for
//     // Server_Finished.
//     seed_fin: Option<[u8; 47]>,
//     // temp storage for a1 from key expansion
//     a1: Option<[u8; 32]>,
//     // inner_hash_p1/p2 from key expansion
//     inner_hash_p1: Option<[u8; 32]>,
//     inner_hash_p2: Option<[u8; 32]>,
//     // verify_data for Client_Finished
//     client_finished_vd: Option<[u8; 12]>,
//     // verify_data for Server_Finished
//     server_finished_vd: Option<[u8; 12]>,
// }

// impl MasterCore for HandshakeMaster {
//     /// The first method that should be called after instantiation. Performs
//     /// setup before we can process master secret related messages.
//     fn ms_setup(&mut self, inner_hash_state: [u32; 8]) -> Result<HandshakeMessage, HandshakeError> {
//         if self.state != State::Initialized {
//             return Err(HandshakeError::WrongState);
//         }
//         let seed = seed_ms(&self.client_random, &self.server_random);
//         // H((pms xor ipad) || seed)
//         let inner_hash = finalize_sha256_digest(inner_hash_state, 64, &seed);
//         self.seed = Some(seed);
//         self.inner_hash_state = Some(inner_hash_state);
//         self.state = State::Ms1;
//         Ok(HandshakeMessage::MasterMs1(MasterMs1 { inner_hash }))
//     }

//     // Performs setup before we can process key expansion related messages.
//     fn ke_setup(&mut self, inner_hash_state: [u32; 8]) -> Result<HandshakeMessage, HandshakeError> {
//         if self.state != State::Ms3 {
//             return Err(HandshakeError::WrongState);
//         }
//         let seed = seed_ke(&self.client_random, &self.server_random);
//         // H((ms xor ipad) || seed)
//         let inner_hash = finalize_sha256_digest(inner_hash_state, 64, &seed);
//         self.seed = Some(seed);
//         self.inner_hash_state = Some(inner_hash_state);
//         self.state = State::Ke1;
//         Ok(HandshakeMessage::MasterKe1(MasterKe1 { inner_hash }))
//     }

//     // Performs setup before we can process Client_Finished related messages.
//     fn cf_setup(&mut self, handshake_blob: &[u8]) -> Result<HandshakeMessage, HandshakeError> {
//         if self.state != State::Ke3 {
//             return Err(HandshakeError::WrongState);
//         }
//         let seed = seed_cf(handshake_blob);
//         // H((ms xor ipad) || seed)
//         let inner_hash = finalize_sha256_digest(self.inner_hash_state.unwrap(), 64, &seed);
//         self.seed_fin = Some(seed);
//         self.state = State::Cf1;
//         Ok(HandshakeMessage::MasterCf1(MasterCf1 { inner_hash }))
//     }

//     // Performs setup before we can process Server_Finished related messages.
//     fn sf_setup(&mut self, handshake_blob: &[u8]) -> Result<HandshakeMessage, HandshakeError> {
//         if self.state != State::Cf3 {
//             return Err(HandshakeError::WrongState);
//         }
//         let seed = seed_sf(handshake_blob);
//         // H((ms xor ipad) || seed)
//         let inner_hash = finalize_sha256_digest(self.inner_hash_state.unwrap(), 64, &seed);
//         self.seed_fin = Some(seed);
//         self.state = State::Sf1;
//         Ok(HandshakeMessage::MasterSf1(MasterSf1 { inner_hash }))
//     }

//     /// Will be called repeatedly whenever there is a message from Slave that
//     /// needs to be processed.
//     fn next(
//         &mut self,
//         message: HandshakeMessage,
//     ) -> Result<Option<HandshakeMessage>, HandshakeError> {
//         match message {
//             HandshakeMessage::SlaveMs1(m) => {
//                 if self.state != State::Ms1 {
//                     return Err(HandshakeError::OutOfOrder);
//                 }
//                 self.state = State::Ms2;
//                 Ok(Some(HandshakeMessage::MasterMs2(MasterMs2 {
//                     inner_hash: self.ms1(&m.a1),
//                 })))
//             }
//             HandshakeMessage::SlaveMs2(m) => {
//                 if self.state != State::Ms2 {
//                     return Err(HandshakeError::OutOfOrder);
//                 }
//                 self.state = State::Ms3;
//                 Ok(Some(HandshakeMessage::MasterMs3(MasterMs3 {
//                     inner_hash: self.ms2(&m.a2),
//                 })))
//             }
//             HandshakeMessage::SlaveKe1(m) => {
//                 if self.state != State::Ke1 {
//                     return Err(HandshakeError::OutOfOrder);
//                 }
//                 self.a1 = Some(m.a1);
//                 self.state = State::Ke2;
//                 Ok(Some(HandshakeMessage::MasterKe2(MasterKe2 {
//                     inner_hash: self.ke1(&m.a1),
//                 })))
//             }
//             HandshakeMessage::SlaveKe2(m) => {
//                 if self.state != State::Ke2 {
//                     return Err(HandshakeError::OutOfOrder);
//                 }
//                 let (ihp1, ihp2) = self.ke2(&m.a2);
//                 self.inner_hash_p1 = Some(ihp1);
//                 self.inner_hash_p2 = Some(ihp2);
//                 self.state = State::Ke3;
//                 Ok(None)
//             }
//             HandshakeMessage::SlaveCf1(m) => {
//                 if self.state != State::Cf1 {
//                     return Err(HandshakeError::OutOfOrder);
//                 }
//                 self.state = State::Cf2;
//                 Ok(Some(HandshakeMessage::MasterCf2(MasterCf2 {
//                     inner_hash: self.cf1(&m.a1),
//                 })))
//             }
//             HandshakeMessage::SlaveCf2(m) => {
//                 if self.state != State::Cf2 {
//                     return Err(HandshakeError::OutOfOrder);
//                 }
//                 self.client_finished_vd = Some(m.verify_data);
//                 self.state = State::Cf3;
//                 Ok(None)
//             }
//             HandshakeMessage::SlaveSf1(m) => {
//                 if self.state != State::Sf1 {
//                     return Err(HandshakeError::OutOfOrder);
//                 }
//                 self.state = State::Sf2;
//                 Ok(Some(HandshakeMessage::MasterSf2(MasterSf2 {
//                     inner_hash: self.sf1(&m.a1),
//                 })))
//             }
//             HandshakeMessage::SlaveSf2(m) => {
//                 if self.state != State::Sf2 {
//                     return Err(HandshakeError::OutOfOrder);
//                 }
//                 self.server_finished_vd = Some(m.verify_data);
//                 self.state = State::Sf3;
//                 Ok(None)
//             }
//             _ => Err(HandshakeError::InvalidMessage),
//         }
//     }

//     fn get_inner_hashes_ke(self) -> ([u8; 32], [u8; 32]) {
//         (self.inner_hash_p1.unwrap(), self.inner_hash_p2.unwrap())
//     }

//     fn get_client_finished_vd(self) -> [u8; 12] {
//         self.client_finished_vd.unwrap()
//     }

//     fn get_server_finished_vd(self) -> [u8; 12] {
//         self.server_finished_vd.unwrap()
//     }
// }

// impl HandshakeMaster {
//     pub fn new(client_random: [u8; 32], server_random: [u8; 32]) -> Self {
//         Self {
//             state: State::Initialized,
//             client_random,
//             server_random,
//             inner_hash_state: None,
//             seed: None,
//             a1: None,
//             inner_hash_p1: None,
//             inner_hash_p2: None,
//             client_finished_vd: None,
//             server_finished_vd: None,
//             seed_fin: None,
//         }
//     }
//     fn ms1(&mut self, a1: &[u8]) -> [u8; 32] {
//         // H((pms xor ipad) || a1)
//         finalize_sha256_digest(self.inner_hash_state.unwrap(), 64, a1)
//     }

//     fn ms2(&mut self, a2: &[u8]) -> [u8; 32] {
//         let mut a2_seed = [0u8; 109];
//         a2_seed[..32].copy_from_slice(a2);
//         a2_seed[32..].copy_from_slice(&self.seed.unwrap());
//         // H((pms xor ipad) || a2 || seed)
//         finalize_sha256_digest(self.inner_hash_state.unwrap(), 64, &a2_seed)
//     }

//     fn ke1(&mut self, a1: &[u8]) -> [u8; 32] {
//         // H((ms xor ipad) || a1)
//         finalize_sha256_digest(self.inner_hash_state.unwrap(), 64, a1)
//     }

//     fn ke2(&mut self, a2: &[u8]) -> ([u8; 32], [u8; 32]) {
//         let mut a1_seed = [0u8; 109];
//         a1_seed[..32].copy_from_slice(&self.a1.unwrap());
//         a1_seed[32..].copy_from_slice(&self.seed.unwrap());

//         let mut a2_seed = [0u8; 109];
//         a2_seed[..32].copy_from_slice(a2);
//         a2_seed[32..].copy_from_slice(&self.seed.unwrap());

//         // H((ms xor ipad) || a1 || seed)
//         let inner_hash_p1 = finalize_sha256_digest(self.inner_hash_state.unwrap(), 64, &a1_seed);

//         // H((ms xor ipad) || a2 || seed)
//         let inner_hash_p2 = finalize_sha256_digest(self.inner_hash_state.unwrap(), 64, &a2_seed);
//         (inner_hash_p1, inner_hash_p2)
//     }

//     fn cf1(&mut self, a1: &[u8]) -> [u8; 32] {
//         // H((ms xor ipad) || a1 || seed)
//         let mut a1_seed = [0u8; 79];
//         a1_seed[..32].copy_from_slice(a1);
//         a1_seed[32..].copy_from_slice(&self.seed_fin.unwrap());
//         finalize_sha256_digest(self.inner_hash_state.unwrap(), 64, &a1_seed)
//     }

//     fn sf1(&mut self, a1: &[u8]) -> [u8; 32] {
//         // H((ms xor ipad) || a1 || seed)
//         let mut a1_seed = [0u8; 79];
//         a1_seed[..32].copy_from_slice(a1);
//         a1_seed[32..].copy_from_slice(&self.seed_fin.unwrap());
//         finalize_sha256_digest(self.inner_hash_state.unwrap(), 64, &a1_seed)
//     }
// }
