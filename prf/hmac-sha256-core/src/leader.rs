use super::{
    sha::finalize_sha256_digest,
    utils::{seed_ke, seed_ms},
};
use crate::msgs;

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
        impl Sealed for super::KeComplete {}
    }

    pub trait State: sealed::Sealed {}

    pub struct Ms1 {}
    pub struct Ms2 {
        pub(super) seed_ms: [u8; 77],
        pub(super) inner_hash_state: [u32; 8],
        pub(super) client_random: [u8; 32],
        pub(super) server_random: [u8; 32],
    }
    pub struct Ms3 {
        pub(super) seed_ms: [u8; 77],
        pub(super) inner_hash_state: [u32; 8],
        pub(super) p1_inner_hash: [u8; 32],
        pub(super) client_random: [u8; 32],
        pub(super) server_random: [u8; 32],
    }
    pub struct MsComplete {
        pub(super) p1_inner_hash: [u8; 32],
        pub(super) client_random: [u8; 32],
        pub(super) server_random: [u8; 32],
    }
    pub struct Ke1 {
        pub(super) client_random: [u8; 32],
        pub(super) server_random: [u8; 32],
    }
    pub struct Ke2 {
        pub(super) seed_ke: [u8; 77],
        pub(super) inner_hash_state: [u32; 8],
    }
    pub struct Ke3 {
        pub(super) seed_ke: [u8; 77],
        pub(super) inner_hash_state: [u32; 8],
        pub(super) a1: [u8; 32],
    }
    pub struct KeComplete {
        pub(super) p1_inner_hash: [u8; 32],
        pub(super) p2_inner_hash: [u8; 32],
    }

    impl State for Ms1 {}
    impl State for Ms2 {}
    impl State for Ms3 {}
    impl State for MsComplete {}
    impl State for Ke1 {}
    impl State for Ke2 {}
    impl State for Ke3 {}
    impl State for KeComplete {}
}

use state::*;

pub struct PRFLeader<S: State = Ms1> {
    state: S,
}

impl PRFLeader<Ms1> {
    /// Creates new PRF leader
    pub fn new() -> PRFLeader<Ms1> {
        PRFLeader { state: Ms1 {} }
    }

    /// Computes a1 inner hash
    /// ```text
    /// H((pms xor ipad) || seed)
    /// ```
    /// Returns message to [`super::PRFFollower`] and next state
    pub fn next(
        self,
        client_random: [u8; 32],
        server_random: [u8; 32],
        inner_hash_state: [u32; 8],
    ) -> (msgs::LeaderMs1, PRFLeader<Ms2>) {
        let seed_ms = seed_ms(&client_random, &server_random);
        let a1_inner_hash = finalize_sha256_digest(inner_hash_state, 64, &seed_ms);
        (
            msgs::LeaderMs1 { a1_inner_hash },
            PRFLeader {
                state: Ms2 {
                    seed_ms,
                    inner_hash_state,
                    client_random,
                    server_random,
                },
            },
        )
    }
}

impl Default for PRFLeader<Ms1> {
    fn default() -> Self {
        Self::new()
    }
}

impl PRFLeader<Ms2> {
    /// Computes p1 and a2 inner hashes
    /// ```text
    /// a2_inner_hash = H((pms xor ipad) || a1)
    /// p1_inner_hash = H((pms xor ipad) || a1 || seed)
    /// ```
    /// Returns message to [`super::PRFFollower`] and next state
    pub fn next(self, msg: msgs::FollowerMs1) -> (msgs::LeaderMs2, PRFLeader<Ms3>) {
        // a1 || seed
        let mut a1_seed = [0u8; 109];
        a1_seed[..32].copy_from_slice(&msg.a1);
        a1_seed[32..].copy_from_slice(&seed_ms(
            &self.state.client_random,
            &self.state.server_random,
        ));
        let p1_inner_hash = finalize_sha256_digest(self.state.inner_hash_state, 64, &a1_seed);
        let a2_inner_hash = finalize_sha256_digest(self.state.inner_hash_state, 64, &msg.a1);
        (
            msgs::LeaderMs2 { a2_inner_hash },
            PRFLeader {
                state: Ms3 {
                    seed_ms: self.state.seed_ms,
                    inner_hash_state: self.state.inner_hash_state,
                    p1_inner_hash,
                    client_random: self.state.client_random,
                    server_random: self.state.server_random,
                },
            },
        )
    }
}

impl PRFLeader<Ms3> {
    /// Computes p2_inner_hash
    /// ```text
    /// p2_inner_hash = H((pms xor ipad) || a2 || seed)
    /// ```
    /// Returns message to [`super::PRFFollower`] and next state
    pub fn next(self, msg: msgs::FollowerMs2) -> (msgs::LeaderMs3, PRFLeader<MsComplete>) {
        let mut a2_seed = [0u8; 109];
        a2_seed[..32].copy_from_slice(&msg.a2);
        a2_seed[32..].copy_from_slice(&self.state.seed_ms);
        // p2 inner hash = H((pms xor ipad) || a2 || seed)
        let p2_inner_hash = finalize_sha256_digest(self.state.inner_hash_state, 64, &a2_seed);
        (
            msgs::LeaderMs3 { p2_inner_hash },
            PRFLeader {
                state: MsComplete {
                    p1_inner_hash: self.state.p1_inner_hash,
                    client_random: self.state.client_random,
                    server_random: self.state.server_random,
                },
            },
        )
    }
}

impl PRFLeader<MsComplete> {
    /// Returns master secret p1 inner hash
    /// ```text
    /// p1_inner_hash = H((pms xor ipad) || a1 || seed)
    /// ```
    pub fn p1_inner_hash(&self) -> [u8; 32] {
        self.state.p1_inner_hash
    }

    /// Returns next state
    pub fn next(self) -> PRFLeader<Ke1> {
        PRFLeader {
            state: Ke1 {
                client_random: self.state.client_random,
                server_random: self.state.server_random,
            },
        }
    }
}

impl PRFLeader<Ke1> {
    /// Computes a1 inner hash
    /// ```text
    /// a1_inner_hash = H((ms xor ipad) || seed)
    /// ```
    /// Returns message to [`super::PRFFollower`] and next state
    pub fn next(self, inner_hash_state: [u32; 8]) -> (msgs::LeaderKe1, PRFLeader<Ke2>) {
        let seed_ke = seed_ke(&self.state.client_random, &self.state.server_random);
        let a1_inner_hash = finalize_sha256_digest(inner_hash_state, 64, &seed_ke);
        (
            msgs::LeaderKe1 { a1_inner_hash },
            PRFLeader {
                state: Ke2 {
                    seed_ke,
                    inner_hash_state,
                },
            },
        )
    }
}

impl PRFLeader<Ke2> {
    /// Computes a2_inner_hash
    /// ```text
    /// a2_inner_hash = H((ms xor ipad) || a1)
    /// ```
    /// Returns message to [`super::PRFFollower`] and next state
    pub fn next(self, msg: msgs::FollowerKe1) -> (msgs::LeaderKe2, PRFLeader<Ke3>) {
        let a2_inner_hash = finalize_sha256_digest(self.state.inner_hash_state, 64, &msg.a1);
        (
            msgs::LeaderKe2 { a2_inner_hash },
            PRFLeader {
                state: Ke3 {
                    seed_ke: self.state.seed_ke,
                    inner_hash_state: self.state.inner_hash_state,
                    a1: msg.a1,
                },
            },
        )
    }
}

impl PRFLeader<Ke3> {
    /// Computes p1 and p2 inner hashes
    /// ```text
    /// p1_inner_hash = H((ms xor ipad) || a1 || seed)
    /// p2_inner_hash = H((ms xor ipad) || a2 || seed)
    /// ```
    /// Returns next state
    pub fn next(self, msg: msgs::FollowerKe2) -> PRFLeader<KeComplete> {
        let mut a1_seed = [0u8; 109];
        a1_seed[..32].copy_from_slice(&self.state.a1);
        a1_seed[32..].copy_from_slice(&self.state.seed_ke);

        let mut a2_seed = [0u8; 109];
        a2_seed[..32].copy_from_slice(&msg.a2);
        a2_seed[32..].copy_from_slice(&self.state.seed_ke);

        // H((ms xor ipad) || a1 || seed)
        let p1_inner_hash = finalize_sha256_digest(self.state.inner_hash_state, 64, &a1_seed);
        // H((ms xor ipad) || a2 || seed)
        let p2_inner_hash = finalize_sha256_digest(self.state.inner_hash_state, 64, &a2_seed);

        PRFLeader {
            state: KeComplete {
                p1_inner_hash,
                p2_inner_hash,
            },
        }
    }
}

impl PRFLeader<KeComplete> {
    /// Returns p1 inner hash from key expansion
    /// ```text
    /// H((ms xor ipad) || a1 || seed)
    /// ```
    pub fn p1_inner_hash(&self) -> [u8; 32] {
        self.state.p1_inner_hash
    }

    /// Returns p2 inner hash from key expansion
    /// ```text
    /// H((ms xor ipad) || a2 || seed)
    /// ```
    pub fn p2_inner_hash(&self) -> [u8; 32] {
        self.state.p2_inner_hash
    }
}
