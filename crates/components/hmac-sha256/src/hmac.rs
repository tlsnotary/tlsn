//! Computation of HMAC-SHA256.
//!
//! HMAC-SHA256 is defined as
//!
//! HMAC(key, m) = H((key' xor opad) || H((key' xor ipad) || m))
//!
//! * H     - SHA256 hash function
//! * key'  - key padded with zero bytes to 64 bytes (we do not support longer
//!   keys)
//! * opad  - 64 bytes of 0x5c
//! * ipad  - 64 bytes of 0x36
//! * m     - message
//!
//! We describe HMAC in terms of the SHA-256 compression function
//! C(IV, m), where `IV` is the hash state, `m` is the input block,
//! and the output is the updated state.
//!
//! HMAC(m) = C( C(IV, key' xor opad),  C( C(IV, key' xor ipad), m) )
//!
//! Throughout this crate we use the following terminology for
//! intermediate states:
//!
//! * `outer_partial` — C(IV, key' ⊕ opad)
//! * `inner_partial` — C(IV, key' ⊕ ipad)
//! * `inner_local`   — C(inner_partial, m)
//!
//! The final value is then computed as:
//!
//! HMAC(m) = C(outer_partial, inner_local)

use std::sync::Arc;

use crate::{
    hmac::{normal::HmacNormal, reduced::HmacReduced},
    sha256, state_to_bytes, Mode,
};
use mpz_circuits::circuits::xor;
use mpz_hash::sha256::Sha256;
use mpz_vm_core::{
    memory::{
        binary::{Binary, U8},
        Array, MemoryExt, Vector, ViewExt,
    },
    Call, CallableExt, Vm,
};

use crate::FError;

pub(crate) mod clear;
pub(crate) mod normal;
pub(crate) mod reduced;

/// Inner padding of HMAC.
pub(crate) const IPAD: [u8; 64] = [0x36; 64];
/// Outer padding of HMAC.
pub(crate) const OPAD: [u8; 64] = [0x5c; 64];
/// Initial IV of SHA256.
pub(crate) const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Functionality for HMAC computation with a private key and a public message.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum Hmac {
    Reduced(reduced::HmacReduced),
    Normal(normal::HmacNormal),
}

impl Hmac {
    /// Allocates a new HMAC with the given `key`.
    pub(crate) fn alloc(
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
        mode: Mode,
    ) -> Result<Self, FError> {
        match mode {
            Mode::Reduced => Ok(Hmac::Reduced(HmacReduced::alloc(vm, key)?)),
            Mode::Normal => Ok(Hmac::Normal(HmacNormal::alloc(vm, key)?)),
        }
    }

    /// Whether this functionality needs to be flushed.
    #[allow(dead_code)]
    pub(crate) fn wants_flush(&self) -> bool {
        match self {
            Hmac::Reduced(hmac) => hmac.wants_flush(),
            Hmac::Normal(hmac) => hmac.wants_flush(),
        }
    }

    /// Flushes the functionality.
    #[allow(dead_code)]
    pub(crate) fn flush(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), FError> {
        match self {
            Hmac::Reduced(hmac) => hmac.flush(vm),
            Hmac::Normal(hmac) => hmac.flush(),
        }
    }

    /// Returns HMAC output.
    #[allow(dead_code)]
    pub(crate) fn output(&self) -> Result<Array<U8, 32>, FError> {
        match self {
            Hmac::Reduced(hmac) => Ok(hmac.output()),
            Hmac::Normal(hmac) => hmac.output(),
        }
    }

    /// Creates a new allocated instance of HMAC from another instance.
    pub(crate) fn from_other(vm: &mut dyn Vm<Binary>, other: &Self) -> Result<Self, FError> {
        match other {
            Hmac::Reduced(hmac) => Ok(Hmac::Reduced(HmacReduced::from_other(vm, hmac)?)),
            Hmac::Normal(hmac) => Ok(Hmac::Normal(HmacNormal::from_other(hmac)?)),
        }
    }
}

/// Computes HMAC-SHA256.
///
/// # Arguments
///
/// * `vm` - The virtual machine.
/// * `outer_partial` - outer_partial.
/// * `inner_local` - inner_local.
pub(crate) fn hmac_sha256(
    vm: &mut dyn Vm<Binary>,
    mut outer_partial: Sha256,
    inner_local: Array<U8, 32>,
) -> Result<Array<U8, 32>, FError> {
    outer_partial.update(&inner_local.into());
    outer_partial.compress(vm)?;
    outer_partial.finalize(vm).map_err(FError::from)
}

/// Depending on the provided `mask` computes and returns outer_partial or
/// inner_partial for HMAC-SHA256.
///
/// # Arguments
///
/// * `vm` - Virtual machine.
/// * `key` - Key to pad and xor.
/// * `mask`- Mask used for padding.
fn compute_partial(
    vm: &mut dyn Vm<Binary>,
    key: Vector<U8>,
    mask: [u8; 64],
) -> Result<Sha256, FError> {
    let xor = Arc::new(xor(8 * 64));

    let additional_len = 64 - key.len();
    let padding = vec![0_u8; additional_len];

    let padding_ref: Vector<U8> = vm.alloc_vec(additional_len).map_err(FError::vm)?;
    vm.mark_public(padding_ref).map_err(FError::vm)?;
    vm.assign(padding_ref, padding).map_err(FError::vm)?;
    vm.commit(padding_ref).map_err(FError::vm)?;

    let mask_ref: Array<U8, 64> = vm.alloc().map_err(FError::vm)?;
    vm.mark_public(mask_ref).map_err(FError::vm)?;
    vm.assign(mask_ref, mask).map_err(FError::vm)?;
    vm.commit(mask_ref).map_err(FError::vm)?;

    let xor = Call::builder(xor)
        .arg(key)
        .arg(padding_ref)
        .arg(mask_ref)
        .build()
        .map_err(FError::vm)?;
    let key_padded: Vector<U8> = vm.call(xor).map_err(FError::vm)?;

    let mut sha = Sha256::new_with_init(vm)?;
    sha.update(&key_padded);
    sha.compress(vm)?;
    Ok(sha)
}

/// Computes and assigns inner_local.
///
/// # Arguments
///
/// * `vm` - Virtual machine.
/// * `inner_local` - VM reference to assign to.
/// * `inner_partial` - inner_partial.
/// * `msg` - Message to be compressed.
pub(crate) fn assign_inner_local(
    vm: &mut dyn Vm<Binary>,
    inner_local: Array<U8, 32>,
    inner_partial: [u32; 8],
    msg: &[u8],
) -> Result<(), FError> {
    let inner_local_value = sha256(inner_partial, 64, msg);

    vm.assign(inner_local, state_to_bytes(inner_local_value))
        .map_err(FError::vm)?;
    vm.commit(inner_local).map_err(FError::vm)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::mock_vm;
    use hmac::{Hmac as HmacReference, Mac};
    use mpz_common::context::test_st_context;
    use mpz_vm_core::{
        memory::{MemoryExt, ViewExt},
        Execute,
    };
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use rstest::*;
    use sha2::Sha256;

    #[rstest]
    #[case::normal(Mode::Normal)]
    #[case::reduced(Mode::Reduced)]
    #[tokio::test]
    async fn test_hmac(#[case] mode: Mode) {
        let mut rng = StdRng::from_seed([2; 32]);

        for _ in 0..10 {
            let key: [u8; 32] = rng.random();
            let msg: [u8; 32] = rng.random();

            let (mut ctx_a, mut ctx_b) = test_st_context(8);
            let (mut leader, mut follower) = mock_vm();

            let vm = &mut leader;
            let key_ref = vm.alloc_vec(32).unwrap();
            vm.mark_public(key_ref).unwrap();
            vm.assign(key_ref, key.to_vec()).unwrap();
            vm.commit(key_ref).unwrap();
            let mut hmac_leader = Hmac::alloc(vm, key_ref, mode).unwrap();

            if mode == Mode::Reduced {
                if let Hmac::Reduced(ref mut hmac) = hmac_leader {
                    hmac.set_msg(&msg).unwrap();
                };
            } else if let Hmac::Normal(ref mut hmac) = hmac_leader {
                let msg_ref = vm.alloc_vec(msg.len()).unwrap();
                vm.mark_public(msg_ref).unwrap();
                vm.assign(msg_ref, msg.to_vec()).unwrap();
                vm.commit(msg_ref).unwrap();
                hmac.set_msg(vm, &[msg_ref]).unwrap();
            }
            let leader_out = hmac_leader.output().unwrap();
            let mut leader_out = vm.decode(leader_out).unwrap();

            let vm = &mut follower;
            let key_ref = vm.alloc_vec(32).unwrap();
            vm.mark_public(key_ref).unwrap();
            vm.assign(key_ref, key.to_vec()).unwrap();
            vm.commit(key_ref).unwrap();
            let mut hmac_follower = Hmac::alloc(vm, key_ref, mode).unwrap();

            if mode == Mode::Reduced {
                if let Hmac::Reduced(ref mut hmac) = hmac_follower {
                    hmac.set_msg(&msg).unwrap();
                };
            } else if let Hmac::Normal(ref mut hmac) = hmac_follower {
                let msg_ref = vm.alloc_vec(msg.len()).unwrap();
                vm.mark_public(msg_ref).unwrap();
                vm.assign(msg_ref, msg.to_vec()).unwrap();
                vm.commit(msg_ref).unwrap();
                hmac.set_msg(vm, &[msg_ref]).unwrap();
            }
            let follower_out = hmac_follower.output().unwrap();
            let mut follower_out = vm.decode(follower_out).unwrap();

            tokio::try_join!(
                async {
                    assert!(hmac_leader.wants_flush());
                    hmac_leader.flush(&mut leader).unwrap();
                    leader.execute_all(&mut ctx_a).await.unwrap();

                    // In reduced mode two flushes are required.
                    if mode == Mode::Reduced {
                        assert!(hmac_leader.wants_flush());
                        hmac_leader.flush(&mut leader).unwrap();
                        leader.execute_all(&mut ctx_a).await.unwrap();
                    }

                    assert!(!hmac_leader.wants_flush());

                    Ok::<(), Box<dyn std::error::Error>>(())
                },
                async {
                    assert!(hmac_follower.wants_flush());
                    hmac_follower.flush(&mut follower).unwrap();
                    follower.execute_all(&mut ctx_b).await.unwrap();

                    // On reduced mode two flushes are required.
                    if mode == Mode::Reduced {
                        assert!(hmac_follower.wants_flush());
                        hmac_follower.flush(&mut follower).unwrap();
                        follower.execute_all(&mut ctx_b).await.unwrap();
                    }

                    assert!(!hmac_follower.wants_flush());

                    Ok::<(), Box<dyn std::error::Error>>(())
                }
            )
            .unwrap();

            let leader_out = leader_out.try_recv().unwrap().unwrap();
            let follower_out = follower_out.try_recv().unwrap().unwrap();

            let mut hmac_ref = HmacReference::<Sha256>::new_from_slice(&key).unwrap();
            hmac_ref.update(&msg);

            assert_eq!(leader_out, follower_out);
            assert_eq!(leader_out, *hmac_ref.finalize().into_bytes());
        }
    }
}
