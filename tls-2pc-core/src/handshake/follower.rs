use super::sha::finalize_sha256_digest;
use crate::msgs::handshake as msgs;

pub mod state {
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
        pub(super) outer_hash_state: [u32; 8],
    }
    pub struct Ms2 {
        pub(super) outer_hash_state: [u32; 8],
    }
    pub struct Ms3 {
        pub(super) outer_hash_state: [u32; 8],
    }
    pub struct Ke1 {}
    pub struct Ke2 {
        pub(super) outer_hash_state: [u32; 8],
    }
    pub struct Ke3 {
        pub(super) outer_hash_state: [u32; 8],
    }
    pub struct Cf1 {
        pub(super) outer_hash_state: [u32; 8],
    }
    pub struct Cf2 {
        pub(super) outer_hash_state: [u32; 8],
    }
    pub struct Sf1 {
        pub(super) outer_hash_state: [u32; 8],
    }
    pub struct Sf2 {
        pub(super) outer_hash_state: [u32; 8],
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
}

use state::*;

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
