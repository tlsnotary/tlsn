use super::sha::finalize_sha256_digest;
use crate::msgs::prf as msgs;

pub mod state {
    mod sealed {
        pub trait Sealed {}
        impl Sealed for super::Ms1 {}
        impl Sealed for super::Ms2 {}
        impl Sealed for super::Ms3 {}
        impl Sealed for super::MsComplete {}
        impl Sealed for super::Ke1 {}
        impl Sealed for super::Ke2 {}
        impl Sealed for super::Ke3 {}
        impl Sealed for super::Cf1 {}
        impl Sealed for super::Cf2 {}
        impl Sealed for super::Sf1 {}
        impl Sealed for super::Sf2 {}
    }

    pub trait State: sealed::Sealed {}

    pub struct Ms1 {}
    pub struct Ms2 {
        pub(super) outer_hash_state: [u32; 8],
    }
    pub struct Ms3 {
        pub(super) outer_hash_state: [u32; 8],
    }
    pub struct MsComplete {
        pub(super) p2: [u8; 32],
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
    impl State for MsComplete {}
    impl State for Ke1 {}
    impl State for Ke2 {}
    impl State for Ke3 {}
    impl State for Cf1 {}
    impl State for Cf2 {}
    impl State for Sf1 {}
    impl State for Sf2 {}
}

use state::*;

pub struct PRFFollower<S: State> {
    state: S,
}

impl PRFFollower<Ms1> {
    /// Returns new PRF follower
    pub fn new() -> PRFFollower<Ms1> {
        PRFFollower { state: Ms1 {} }
    }

    /// Computes a1
    /// ```text
    /// H((pms xor opad) || H((pms xor ipad) || seed))
    /// ```
    /// Returns message to [`super::PRFLeader`] and next state
    pub fn next(
        self,
        outer_hash_state: [u32; 8],
        msg: msgs::LeaderMs1,
    ) -> (msgs::FollowerMs1, PRFFollower<Ms2>) {
        (
            msgs::FollowerMs1 {
                a1: finalize_sha256_digest(outer_hash_state, 64, &msg.a1_inner_hash),
            },
            PRFFollower {
                state: Ms2 { outer_hash_state },
            },
        )
    }
}

impl PRFFollower<Ms2> {
    /// Computes a2
    /// ```text
    /// H((pms xor opad) || H((pms xor ipad) || a1))
    /// ```
    /// Returns message to [`super::PRFLeader`] and next state
    pub fn next(self, msg: msgs::LeaderMs2) -> (msgs::FollowerMs2, PRFFollower<Ms3>) {
        (
            msgs::FollowerMs2 {
                a2: finalize_sha256_digest(self.state.outer_hash_state, 64, &msg.a2_inner_hash),
            },
            PRFFollower {
                state: Ms3 {
                    outer_hash_state: self.state.outer_hash_state,
                },
            },
        )
    }
}

impl PRFFollower<Ms3> {
    /// Computes p2
    /// ```text
    /// H((pms xor opad) || H((pms xor ipad) || a2 || seed))
    /// ```
    /// Returns message to [`super::PRFLeader`] and next state
    pub fn next(self, msg: msgs::LeaderMs3) -> PRFFollower<MsComplete> {
        let p2 = finalize_sha256_digest(self.state.outer_hash_state, 64, &msg.p2_inner_hash);
        PRFFollower {
            state: MsComplete { p2 },
        }
    }
}

impl PRFFollower<MsComplete> {
    /// Returns master secret p2
    /// ```text
    /// H((pms xor opad) || H((pms xor ipad) || a2 || seed))
    /// ```
    pub fn p2(&self) -> [u8; 32] {
        self.state.p2
    }

    /// Returns next state
    pub fn next(self) -> PRFFollower<Ke1> {
        PRFFollower { state: Ke1 {} }
    }
}

impl PRFFollower<Ke1> {
    /// Returns next state
    pub fn next(self, outer_hash_state: [u32; 8]) -> PRFFollower<Ke2> {
        PRFFollower {
            state: Ke2 { outer_hash_state },
        }
    }
}

impl PRFFollower<Ke2> {
    /// Computes a1
    /// ```text
    /// H((ms xor opad) || H((ms xor ipad) || seed))
    /// ```
    /// Returns message to [`super::PRFLeader`] and next state
    pub fn next(self, msg: msgs::LeaderKe1) -> (msgs::FollowerKe1, PRFFollower<Ke3>) {
        (
            msgs::FollowerKe1 {
                a1: finalize_sha256_digest(self.state.outer_hash_state, 64, &msg.a1_inner_hash),
            },
            PRFFollower {
                state: Ke3 {
                    outer_hash_state: self.state.outer_hash_state,
                },
            },
        )
    }
}

impl PRFFollower<Ke3> {
    /// Computes a2
    /// ```text
    /// H((ms xor opad) || H((ms xor ipad) || a1))
    /// ```
    /// Returns message to [`super::PRFLeader`] and next state
    pub fn next(self, msg: msgs::LeaderKe2) -> (msgs::FollowerKe2, PRFFollower<Cf1>) {
        (
            msgs::FollowerKe2 {
                a2: finalize_sha256_digest(self.state.outer_hash_state, 64, &msg.a2_inner_hash),
            },
            PRFFollower {
                state: Cf1 {
                    outer_hash_state: self.state.outer_hash_state,
                },
            },
        )
    }
}

impl PRFFollower<Cf1> {
    /// Computes a1
    /// ```text
    /// H((ms xor opad) || H((ms xor ipad) || cf_seed))
    /// ```
    /// Returns message to [`super::PRFLeader`] and next state
    pub fn next(self, msg: msgs::LeaderCf1) -> (msgs::FollowerCf1, PRFFollower<Cf2>) {
        (
            msgs::FollowerCf1 {
                a1: finalize_sha256_digest(self.state.outer_hash_state, 64, &msg.a1_inner_hash),
            },
            PRFFollower {
                state: Cf2 {
                    outer_hash_state: self.state.outer_hash_state,
                },
            },
        )
    }
}

impl PRFFollower<Cf2> {
    /// Computes client finished verify_data
    /// ```text
    /// H((ms xor opad) || H((ms xor ipad) || a1 || cf_seed))
    /// ```
    /// Returns message to [`super::PRFLeader`] and next state
    pub fn next(self, msg: msgs::LeaderCf2) -> (msgs::FollowerCf2, PRFFollower<Sf1>) {
        let p1 = finalize_sha256_digest(self.state.outer_hash_state, 64, &msg.p1_inner_hash);
        let mut verify_data = [0u8; 12];
        verify_data.copy_from_slice(&p1[..12]);
        (
            msgs::FollowerCf2 { verify_data },
            PRFFollower {
                state: Sf1 {
                    outer_hash_state: self.state.outer_hash_state,
                },
            },
        )
    }
}

impl PRFFollower<Sf1> {
    /// Computes a1
    /// ```text
    /// H((ms xor opad) || H((ms xor ipad) || sf_seed))
    /// ```
    /// Returns message to [`super::PRFLeader`] and next state
    pub fn next(self, msg: msgs::LeaderSf1) -> (msgs::FollowerSf1, PRFFollower<Sf2>) {
        (
            msgs::FollowerSf1 {
                a1: finalize_sha256_digest(self.state.outer_hash_state, 64, &msg.a1_inner_hash),
            },
            PRFFollower {
                state: Sf2 {
                    outer_hash_state: self.state.outer_hash_state,
                },
            },
        )
    }
}

impl PRFFollower<Sf2> {
    /// Computes server finished verify_data
    /// ```text
    /// H((ms xor opad) || H((ms xor ipad) || a1 || sf_seed))
    /// ```
    /// Returns message to [`super::PRFLeader`]
    pub fn next(self, msg: msgs::LeaderSf2) -> msgs::FollowerSf2 {
        let p1 = finalize_sha256_digest(self.state.outer_hash_state, 64, &msg.sf_vd_inner_hash);
        let mut verify_data = [0u8; 12];
        verify_data.copy_from_slice(&p1[..12]);
        msgs::FollowerSf2 { verify_data }
    }
}
