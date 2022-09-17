use super::{
    sha::finalize_sha256_digest,
    utils::{seed_cf, seed_ke, seed_ms, seed_sf},
};
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
        impl Sealed for super::Cf3 {}
        impl Sealed for super::Sf1 {}
        impl Sealed for super::Sf2 {}
        impl Sealed for super::Sf3 {}
    }

    pub trait State: sealed::Sealed {}

    pub struct Ms1 {
        pub(super) inner_hash_state: [u32; 8],
    }
    pub struct Ms2 {
        pub(super) seed_ms: [u8; 77],
        pub(super) inner_hash_state: [u32; 8],
    }
    pub struct Ms3 {
        pub(super) seed_ms: [u8; 77],
        pub(super) inner_hash_state: [u32; 8],
    }
    pub struct Ke1 {}
    pub struct Ke2 {
        pub(super) seed_ke: [u8; 77],
        pub(super) inner_hash_state: [u32; 8],
    }
    pub struct Ke3 {
        pub(super) seed_ke: [u8; 77],
        pub(super) inner_hash_state: [u32; 8],
        pub(super) a1: [u8; 32],
    }
    pub struct Cf1 {
        pub(super) inner_hash_state: [u32; 8],
    }
    pub struct Cf2 {
        pub(super) seed_cf: [u8; 47],
        pub(super) inner_hash_state: [u32; 8],
    }
    pub struct Cf3 {
        pub(super) inner_hash_state: [u32; 8],
    }
    pub struct Sf1 {
        pub(super) inner_hash_state: [u32; 8],
    }
    pub struct Sf2 {
        pub(super) inner_hash_state: [u32; 8],
        pub(super) seed_sf: [u8; 47],
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
}

use state::*;

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
