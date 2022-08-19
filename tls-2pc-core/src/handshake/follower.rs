use super::sha::finalize_sha256_digest;
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
    impl Sealed for super::Sf1 {}
    impl Sealed for super::Sf2 {}
}

pub trait State: sealed::Sealed {}

pub struct Ms1 {
    outer_hash_state: [u32; 8],
}
pub struct Ms2 {
    outer_hash_state: [u32; 8],
}
pub struct Ms3 {
    outer_hash_state: [u32; 8],
}
pub struct Ke1 {}
pub struct Ke2 {
    outer_hash_state: [u32; 8],
}
pub struct Ke3 {
    outer_hash_state: [u32; 8],
}
pub struct Cf1 {
    outer_hash_state: [u32; 8],
}
pub struct Cf2 {
    outer_hash_state: [u32; 8],
}
pub struct Sf1 {
    outer_hash_state: [u32; 8],
}
pub struct Sf2 {
    outer_hash_state: [u32; 8],
}

impl State for Ms1 {}
impl State for Ms2 {}
impl State for Ms3 {}
impl State for Ke1 {}
impl State for Ke2 {}
impl State for Ke3 {}
impl State for Cf1 {}
impl State for Cf2 {}
impl State for Sf1 {}
impl State for Sf2 {}

pub struct HandshakeFollower<S: State> {
    state: S,
}

impl HandshakeFollower<Ms1> {
    pub fn new(outer_hash_state: [u32; 8]) -> HandshakeFollower<Ms1> {
        HandshakeFollower {
            state: Ms1 { outer_hash_state },
        }
    }

    /// H((pms xor opad) || H((pms xor ipad) || seed))
    pub fn next(self, msg: msgs::LeaderMs1) -> (msgs::FollowerMs1, HandshakeFollower<Ms2>) {
        (
            msgs::FollowerMs1 {
                a1: finalize_sha256_digest(self.state.outer_hash_state, 64, &msg.inner_hash),
            },
            HandshakeFollower {
                state: Ms2 {
                    outer_hash_state: self.state.outer_hash_state,
                },
            },
        )
    }
}

impl HandshakeFollower<Ms2> {
    /// H((pms xor opad) || H((pms xor ipad) || a1))
    pub fn next(self, msg: msgs::LeaderMs2) -> (msgs::FollowerMs2, HandshakeFollower<Ms3>) {
        (
            msgs::FollowerMs2 {
                a2: finalize_sha256_digest(self.state.outer_hash_state, 64, &msg.inner_hash),
            },
            HandshakeFollower {
                state: Ms3 {
                    outer_hash_state: self.state.outer_hash_state,
                },
            },
        )
    }
}

impl HandshakeFollower<Ms3> {
    /// H((pms xor opad) || H((pms xor ipad) || a2 || seed))
    pub fn next(self, msg: msgs::LeaderMs3) -> (msgs::FollowerMs3, HandshakeFollower<Ke1>) {
        (
            msgs::FollowerMs3 {
                p2: finalize_sha256_digest(self.state.outer_hash_state, 64, &msg.inner_hash),
            },
            HandshakeFollower { state: Ke1 {} },
        )
    }
}

impl HandshakeFollower<Ke1> {
    pub fn next(self, outer_hash_state: [u32; 8]) -> HandshakeFollower<Ke2> {
        HandshakeFollower {
            state: Ke2 { outer_hash_state },
        }
    }
}

impl HandshakeFollower<Ke2> {
    /// H((ms xor opad) || H((ms xor ipad) || seed))
    pub fn next(self, msg: msgs::LeaderKe1) -> (msgs::FollowerKe2, HandshakeFollower<Ke3>) {
        (
            msgs::FollowerKe2 {
                a1: finalize_sha256_digest(self.state.outer_hash_state, 64, &msg.inner_hash),
            },
            HandshakeFollower {
                state: Ke3 {
                    outer_hash_state: self.state.outer_hash_state,
                },
            },
        )
    }
}

impl HandshakeFollower<Ke3> {
    /// H((ms xor opad) || H((ms xor ipad) || a1))
    pub fn next(self, msg: msgs::LeaderKe2) -> (msgs::FollowerKe3, HandshakeFollower<Cf1>) {
        (
            msgs::FollowerKe3 {
                a2: finalize_sha256_digest(self.state.outer_hash_state, 64, &msg.inner_hash),
            },
            HandshakeFollower {
                state: Cf1 {
                    outer_hash_state: self.state.outer_hash_state,
                },
            },
        )
    }
}

impl HandshakeFollower<Cf1> {
    /// H((ms xor opad) || H((ms xor ipad) || seed))
    pub fn next(self, msg: msgs::LeaderCf1) -> (msgs::FollowerCf1, HandshakeFollower<Cf2>) {
        (
            msgs::FollowerCf1 {
                a1: finalize_sha256_digest(self.state.outer_hash_state, 64, &msg.inner_hash),
            },
            HandshakeFollower {
                state: Cf2 {
                    outer_hash_state: self.state.outer_hash_state,
                },
            },
        )
    }
}

impl HandshakeFollower<Cf2> {
    /// H((ms xor opad) || H((ms xor ipad) || a1 || seed))
    pub fn next(self, msg: msgs::LeaderCf2) -> (msgs::FollowerCf2, HandshakeFollower<Sf1>) {
        let p1 = finalize_sha256_digest(self.state.outer_hash_state, 64, &msg.inner_hash);
        let mut verify_data = [0u8; 12];
        verify_data.copy_from_slice(&p1[..12]);
        (
            msgs::FollowerCf2 { verify_data },
            HandshakeFollower {
                state: Sf1 {
                    outer_hash_state: self.state.outer_hash_state,
                },
            },
        )
    }
}

impl HandshakeFollower<Sf1> {
    /// H((ms xor opad) || H((ms xor ipad) || seed))
    pub fn next(self, msg: msgs::LeaderSf1) -> (msgs::FollowerSf1, HandshakeFollower<Sf2>) {
        (
            msgs::FollowerSf1 {
                a1: finalize_sha256_digest(self.state.outer_hash_state, 64, &msg.inner_hash),
            },
            HandshakeFollower {
                state: Sf2 {
                    outer_hash_state: self.state.outer_hash_state,
                },
            },
        )
    }
}

impl HandshakeFollower<Sf2> {
    /// H((ms xor opad) || H((ms xor ipad) || a1 || seed))
    pub fn next(self, msg: msgs::LeaderSf2) -> msgs::FollowerSf2 {
        let p1 = finalize_sha256_digest(self.state.outer_hash_state, 64, &msg.inner_hash);
        let mut verify_data = [0u8; 12];
        verify_data.copy_from_slice(&p1[..12]);
        msgs::FollowerSf2 { verify_data }
    }
}

// #[derive(Copy, Clone)]
// pub struct HandshakeSlave {
//     state: State,
//     // Depending on the state, the outer hash state will be used for master
//     // secret or for key expansion.
//     outer_hash_state: Option<[u32; 8]>,
// }

// impl SlaveCore for HandshakeSlave {
//     /// The first method that should be called after instantiation. Performs
//     /// setup before we can process master secret related messages.
//     fn ms_setup(&mut self, outer_hash_state: [u32; 8]) -> Result<(), HandshakeError> {
//         if self.state != State::Initialized {
//             return Err(HandshakeError::WrongState);
//         }
//         self.outer_hash_state = Some(outer_hash_state);
//         self.state = State::MsSetup;
//         Ok(())
//     }

//     // Performs setup before we can process key expansion related messages.
//     fn ke_setup(&mut self, outer_hash_state: [u32; 8]) -> Result<(), HandshakeError> {
//         if self.state != State::Ms3 {
//             return Err(HandshakeError::WrongState);
//         }
//         self.outer_hash_state = Some(outer_hash_state);
//         self.state = State::KeSetup;
//         Ok(())
//     }

//     /// Will be called repeatedly whenever there is a message from Master that
//     /// needs to be processed.
//     fn next(&mut self, message: HandshakeMessage) -> Result<HandshakeMessage, HandshakeError> {
//         match message {
//             HandshakeMessage::MasterMs1(m) => {
//                 if self.state != State::MsSetup {
//                     return Err(HandshakeError::WrongState);
//                 }
//                 self.state = State::Ms1;
//                 Ok(HandshakeMessage::SlaveMs1(SlaveMs1 {
//                     a1: self.ms1(&m.inner_hash),
//                 }))
//             }
//             HandshakeMessage::MasterMs2(m) => {
//                 if self.state != State::Ms1 {
//                     return Err(HandshakeError::OutOfOrder);
//                 }
//                 self.state = State::Ms2;
//                 Ok(HandshakeMessage::SlaveMs2(SlaveMs2 {
//                     a2: self.ms2(&m.inner_hash),
//                 }))
//             }
//             HandshakeMessage::MasterMs3(m) => {
//                 if self.state != State::Ms2 {
//                     return Err(HandshakeError::OutOfOrder);
//                 }
//                 self.state = State::Ms3;
//                 Ok(HandshakeMessage::SlaveMs3(SlaveMs3 {
//                     p2: self.ms3(&m.inner_hash),
//                 }))
//             }
//             HandshakeMessage::MasterKe1(m) => {
//                 if self.state != State::KeSetup {
//                     return Err(HandshakeError::WrongState);
//                 }
//                 self.state = State::Ke1;
//                 Ok(HandshakeMessage::SlaveKe1(SlaveKe1 {
//                     a1: self.ke1(&m.inner_hash),
//                 }))
//             }
//             HandshakeMessage::MasterKe2(m) => {
//                 if self.state != State::Ke1 {
//                     return Err(HandshakeError::OutOfOrder);
//                 }
//                 self.state = State::Ke2;
//                 Ok(HandshakeMessage::SlaveKe2(SlaveKe2 {
//                     a2: self.ke2(&m.inner_hash),
//                 }))
//             }
//             HandshakeMessage::MasterCf1(m) => {
//                 if self.state != State::Ke2 {
//                     return Err(HandshakeError::OutOfOrder);
//                 }
//                 self.state = State::Cf1;
//                 Ok(HandshakeMessage::SlaveCf1(SlaveCf1 {
//                     a1: self.cf1(&m.inner_hash),
//                 }))
//             }
//             HandshakeMessage::MasterCf2(m) => {
//                 if self.state != State::Cf1 {
//                     return Err(HandshakeError::OutOfOrder);
//                 }
//                 self.state = State::Cf2;
//                 Ok(HandshakeMessage::SlaveCf2(SlaveCf2 {
//                     verify_data: self.cf2(&m.inner_hash),
//                 }))
//             }
//             HandshakeMessage::MasterSf1(m) => {
//                 if self.state != State::Cf2 {
//                     return Err(HandshakeError::OutOfOrder);
//                 }
//                 self.state = State::Sf1;
//                 Ok(HandshakeMessage::SlaveSf1(SlaveSf1 {
//                     a1: self.sf1(&m.inner_hash),
//                 }))
//             }
//             HandshakeMessage::MasterSf2(m) => {
//                 if self.state != State::Sf1 {
//                     return Err(HandshakeError::OutOfOrder);
//                 }
//                 self.state = State::Sf2;
//                 Ok(HandshakeMessage::SlaveSf2(SlaveSf2 {
//                     verify_data: self.sf2(&m.inner_hash),
//                 }))
//             }
//             _ => Err(HandshakeError::InvalidMessage),
//         }
//     }
// }

// impl HandshakeSlave {
//     pub fn new() -> Self {
//         Self {
//             state: State::Initialized,
//             outer_hash_state: None,
//         }
//     }

//     fn ms1(&mut self, inner_hash: &[u8]) -> [u8; 32] {
//         // H((pms xor opad) || H((pms xor ipad) || seed))
//         finalize_sha256_digest(self.outer_hash_state.unwrap(), 64, inner_hash)
//     }

//     fn ms2(&mut self, inner_hash: &[u8]) -> [u8; 32] {
//         // H((pms xor opad) || H((pms xor ipad) || a1))
//         finalize_sha256_digest(self.outer_hash_state.unwrap(), 64, inner_hash)
//     }

//     fn ms3(&mut self, inner_hash: &[u8]) -> [u8; 32] {
//         // H((pms xor opad) || H((pms xor ipad) || a2 || seed))
//         finalize_sha256_digest(self.outer_hash_state.unwrap(), 64, inner_hash)
//     }

//     fn ke1(&mut self, inner_hash: &[u8]) -> [u8; 32] {
//         // H((ms xor opad) || H((ms xor ipad) || seed))
//         finalize_sha256_digest(self.outer_hash_state.unwrap(), 64, inner_hash)
//     }

//     fn ke2(&mut self, inner_hash: &[u8]) -> [u8; 32] {
//         // H((ms xor opad) || H((ms xor ipad) || a1))
//         finalize_sha256_digest(self.outer_hash_state.unwrap(), 64, inner_hash)
//     }

//     fn cf1(&mut self, inner_hash: &[u8]) -> [u8; 32] {
//         // H((ms xor opad) || H((ms xor ipad) || seed))
//         finalize_sha256_digest(self.outer_hash_state.unwrap(), 64, inner_hash)
//     }

//     fn cf2(&mut self, inner_hash: &[u8]) -> [u8; 12] {
//         // H((ms xor opad) || H((ms xor ipad) || a1 || seed))
//         let p1 = finalize_sha256_digest(self.outer_hash_state.unwrap(), 64, inner_hash);
//         let mut verify_data = [0u8; 12];
//         verify_data.copy_from_slice(&p1[..12]);
//         verify_data
//     }

//     fn sf1(&mut self, inner_hash: &[u8]) -> [u8; 32] {
//         // H((ms xor opad) || H((ms xor ipad) || seed))
//         finalize_sha256_digest(self.outer_hash_state.unwrap(), 64, inner_hash)
//     }

//     fn sf2(&mut self, inner_hash: &[u8]) -> [u8; 12] {
//         // H((ms xor opad) || H((ms xor ipad) || a1 || seed))
//         let p1 = finalize_sha256_digest(self.outer_hash_state.unwrap(), 64, inner_hash);
//         let mut verify_data = [0u8; 12];
//         verify_data.copy_from_slice(&p1[..12]);
//         verify_data
//     }
// }
