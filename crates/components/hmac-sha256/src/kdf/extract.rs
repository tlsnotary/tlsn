//! `HKDF-Extract` function as defined in https://datatracker.ietf.org/doc/html/rfc5869

use crate::{
    hmac::{normal::HmacNormal, Hmac},
    FError, Mode,
};
use mpz_vm_core::{
    memory::{
        binary::{Binary, U8},
        Array, Vector,
    },
    Vm,
};

pub(crate) mod normal;
pub(crate) mod reduced;

/// Functionality for computing `HKDF-Extract` with private salt and public
/// IKM.
#[derive(Debug)]
pub(crate) enum HkdfExtract {
    Reduced(reduced::HkdfExtract),
    Normal(normal::HkdfExtract),
}

impl HkdfExtract {
    /// Allocates a new HKDF-Extract with the given `ikm` and `hmac`
    /// instantiated with the salt.
    pub(crate) fn alloc(
        mode: Mode,
        vm: &mut dyn Vm<Binary>,
        ikm: [u8; 32],
        hmac: Hmac,
    ) -> Result<Self, FError> {
        let prf = match mode {
            Mode::Reduced => {
                if let Hmac::Reduced(hmac) = hmac {
                    Self::Reduced(reduced::HkdfExtract::alloc(ikm, hmac)?)
                } else {
                    unreachable!("modes always match");
                }
            }
            Mode::Normal => {
                if let Hmac::Normal(hmac) = hmac {
                    Self::Normal(normal::HkdfExtract::alloc(vm, ikm, hmac)?)
                } else {
                    unreachable!("modes always match");
                }
            }
        };
        Ok(prf)
    }

    /// Whether this functionality needs to be flushed.
    pub(crate) fn wants_flush(&self) -> bool {
        match self {
            HkdfExtract::Reduced(hkdf) => hkdf.wants_flush(),
            HkdfExtract::Normal(hkdf) => hkdf.wants_flush(),
        }
    }

    /// Flushes the functionality.
    pub(crate) fn flush(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), FError> {
        match self {
            HkdfExtract::Reduced(hkdf) => hkdf.flush(vm),
            HkdfExtract::Normal(hkdf) => hkdf.flush(),
        }
    }

    /// Returns HKDF-Extract output.
    pub(crate) fn output(&self) -> Vector<U8> {
        match self {
            HkdfExtract::Reduced(hkdf) => hkdf.output(),
            HkdfExtract::Normal(hkdf) => hkdf.output(),
        }
    }

    /// Whether this functionality is complete.
    pub(crate) fn is_complete(&self) -> bool {
        match self {
            HkdfExtract::Reduced(hkdf) => hkdf.is_complete(),
            HkdfExtract::Normal(hkdf) => hkdf.is_complete(),
        }
    }
}

/// Functionality for computing `HKDF-Extract` with private IKM and public
/// salt.
#[derive(Debug)]
pub(crate) struct HkdfExtractPrivIkm {
    output: Vector<U8>,
    state: State,
}

impl HkdfExtractPrivIkm {
    /// Allocates a new HKDF-Extract with the given `ikm` and `hmac`
    /// instantiated with the salt.
    pub(crate) fn alloc(
        vm: &mut dyn Vm<Binary>,
        ikm: Array<U8, 32>,
        mut hmac: HmacNormal,
    ) -> Result<Self, FError> {
        hmac.set_msg(vm, &[ikm.into()])?;

        Ok(Self {
            output: hmac.output()?.into(),
            state: State::Setup,
        })
    }

    /// Whether this functionality needs to be flushed.
    pub(crate) fn wants_flush(&self) -> bool {
        matches!(self.state, State::Setup)
    }

    /// Flushes the functionality.
    pub(crate) fn flush(&mut self) {
        if let State::Setup = self.state {
            self.state = State::Complete;
        }
    }

    /// Returns HKDF-Extract output.
    pub(crate) fn output(&self) -> Vector<U8> {
        self.output
    }

    pub(crate) fn is_complete(&self) -> bool {
        matches!(self.state, State::Complete)
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(crate) enum State {
    Setup,
    Complete,
}

#[cfg(test)]
mod tests {
    use crate::{
        hmac::{clear, normal::HmacNormal, Hmac},
        kdf::extract::{HkdfExtract, HkdfExtractPrivIkm},
        test_utils::mock_vm,
        Mode,
    };
    use mpz_common::context::test_st_context;
    use mpz_vm_core::{
        memory::{binary::U8, Array, MemoryExt, ViewExt},
        Execute,
    };
    use rstest::*;

    #[tokio::test]
    async fn test_hkdf_extract_priv_ikm() {
        for fixture in test_fixtures() {
            let (salt, ikm, secret) = fixture;

            let (mut ctx_a, mut ctx_b) = test_st_context(8);
            let (mut leader, mut follower) = mock_vm();

            let ikm: [u8; 32] = ikm.try_into().unwrap();

            let inner_state = clear::compute_inner_partial(&salt);
            let outer_state = clear::compute_outer_partial(&salt);

            // ------------------ LEADER

            let vm = &mut leader;

            let ikm_ref: Array<U8, 32> = vm.alloc().unwrap();
            vm.mark_public(ikm_ref).unwrap();
            vm.assign(ikm_ref, ikm).unwrap();
            vm.commit(ikm_ref).unwrap();

            let hmac = HmacNormal::alloc_with_state(vm, inner_state, outer_state).unwrap();

            let mut hkdf_leader = HkdfExtractPrivIkm::alloc(vm, ikm_ref, hmac).unwrap();
            let out_leader = hkdf_leader.output();
            let mut leader_decode_fut = vm.decode(out_leader).unwrap();

            // ------------------ FOLLOWER

            let vm = &mut follower;

            let ikm_ref: Array<U8, 32> = vm.alloc().unwrap();
            vm.mark_public(ikm_ref).unwrap();
            vm.assign(ikm_ref, ikm).unwrap();
            vm.commit(ikm_ref).unwrap();

            let hmac = HmacNormal::alloc_with_state(vm, inner_state, outer_state).unwrap();

            let mut hkdf_follower = HkdfExtractPrivIkm::alloc(vm, ikm_ref, hmac).unwrap();
            let out_follower = hkdf_follower.output();
            let mut follower_decode_fut = vm.decode(out_follower).unwrap();

            tokio::try_join!(
                async {
                    leader.execute_all(&mut ctx_a).await.unwrap();
                    assert!(hkdf_leader.wants_flush());
                    hkdf_leader.flush();
                    assert!(!hkdf_leader.wants_flush());

                    Ok::<(), Box<dyn std::error::Error>>(())
                },
                async {
                    follower.execute_all(&mut ctx_b).await.unwrap();
                    assert!(hkdf_follower.wants_flush());
                    hkdf_follower.flush();
                    assert!(!hkdf_follower.wants_flush());

                    Ok::<(), Box<dyn std::error::Error>>(())
                }
            )
            .unwrap();

            let leader_out = leader_decode_fut.try_recv().unwrap().unwrap();
            let follower_out = follower_decode_fut.try_recv().unwrap().unwrap();
            assert_eq!(leader_out, follower_out);
            assert_eq!(leader_out, secret);
        }
    }

    #[rstest]
    #[case::normal(Mode::Normal)]
    #[case::reduced(Mode::Reduced)]
    #[tokio::test]
    async fn test_hkdf_extract(#[case] mode: Mode) {
        for fixture in test_fixtures() {
            let (salt, ikm, secret) = fixture;

            let (mut ctx_a, mut ctx_b) = test_st_context(8);
            let (mut leader, mut follower) = mock_vm();

            let salt: [u8; 32] = salt.try_into().unwrap();

            // ------------------ LEADER

            let vm = &mut leader;

            let salt_ref = vm.alloc_vec(32).unwrap();
            vm.mark_public(salt_ref).unwrap();
            vm.assign(salt_ref, salt.to_vec()).unwrap();
            vm.commit(salt_ref).unwrap();

            let hmac = Hmac::alloc(vm, salt_ref, mode).unwrap();

            let mut hkdf_leader =
                HkdfExtract::alloc(mode, vm, ikm.clone().try_into().unwrap(), hmac).unwrap();
            let out_leader = hkdf_leader.output();
            let mut leader_decode_fut = leader.decode(out_leader).unwrap();

            // ------------------ FOLLOWER

            let vm = &mut follower;

            let salt_ref = vm.alloc_vec(32).unwrap();
            vm.mark_public(salt_ref).unwrap();
            vm.assign(salt_ref, salt.to_vec()).unwrap();
            vm.commit(salt_ref).unwrap();

            let hmac = Hmac::alloc(vm, salt_ref, mode).unwrap();

            let mut hkdf_follower =
                HkdfExtract::alloc(mode, vm, ikm.try_into().unwrap(), hmac).unwrap();
            let out_follower = hkdf_follower.output();
            let mut follower_decode_fut = follower.decode(out_follower).unwrap();

            tokio::try_join!(
                async {
                    leader.execute_all(&mut ctx_a).await.unwrap();
                    assert!(hkdf_leader.wants_flush());
                    hkdf_leader.flush(&mut leader).unwrap();
                    assert!(!hkdf_leader.wants_flush());
                    leader.execute_all(&mut ctx_a).await.unwrap();

                    Ok::<(), Box<dyn std::error::Error>>(())
                },
                async {
                    follower.execute_all(&mut ctx_b).await.unwrap();
                    assert!(hkdf_follower.wants_flush());
                    hkdf_follower.flush(&mut follower).unwrap();
                    assert!(!hkdf_follower.wants_flush());
                    follower.execute_all(&mut ctx_b).await.unwrap();

                    Ok::<(), Box<dyn std::error::Error>>(())
                }
            )
            .unwrap();

            let out_leader = leader_decode_fut.try_recv().unwrap().unwrap();
            let out_follower = follower_decode_fut.try_recv().unwrap().unwrap();
            assert_eq!(out_leader, out_follower);
            assert_eq!(out_leader, secret);
        }
    }

    // Reference values from https://datatracker.ietf.org/doc/html/draft-ietf-tls-tls13-vectors-06
    fn test_fixtures() -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        vec![(
            // SALT
            from_hex_str::<32>("6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba").to_vec(),
            // IKM
            from_hex_str::<32>("81 51 d1 46 4c 1b 55 53 36 23 b9 c2 24 6a 6a 0e 6e 7e 18 50 63 e1 4a fd af f0 b6 e1 c6 1a 86 42").to_vec(),
            // SECRET
            from_hex_str::<32>("5b 4f 96 5d f0 3c 68 2c 46 e6 ee 86 c3 11 63 66 15 a1 d2 bb b2 43 45 c2 52 05 95 3c 87 9e 8d 06").to_vec(),
        ),
        (
            // SALT
            from_hex_str::<32>("c8 61 57 19 e2 40 37 47 b6 10 76 2c 72 b8 f4 da 5c 60 99 57 65 d4 04 a9 d0 06 b9 b0 72 7b a5 83").to_vec(),
            // IKM
            from_hex_str::<32>("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00").to_vec(),
            // SECRET
            from_hex_str::<32>("5c 79 d1 69 42 4e 26 2b 56 32 03 62 7b e4 eb 51 03 3f 58 8c 43 c9 ce 03 73 37 2d bc bc 01 85 a7").to_vec(),
        ),
        (
            // SALT
            from_hex_str::<32>("9e fc 79 87 0b 08 c4 c6 51 20 52 50 af 9b 83 04 79 11 b7 83 d5 d7 67 8d 7c cc e7 18 18 9e a2 ec").to_vec(),
            // IKM
            from_hex_str::<32>("b0 66 a1 5b c1 aa ee f8 79 0e 0b 02 e6 2f 82 dc 44 64 46 e3 7d 6d 61 22 b0 d3 b9 94 ef 11 dd 3c").to_vec(),
            // SECRET
            from_hex_str::<32>("ea d8 b8 c5 9a 15 df 29 d7 9f a4 ac 31 d5 f7 c9 0e 2e 5c 87 d9 ea fe d1 fe 69 16 cf 2f 29 37 34").to_vec(),
        )
        ]
    }

    fn from_hex_str<const N: usize>(s: &str) -> [u8; N] {
        let bytes: Vec<u8> = hex::decode(s.split_whitespace().collect::<String>()).unwrap();
        bytes
            .try_into()
            .expect("Hex string length does not match array size")
    }
}
