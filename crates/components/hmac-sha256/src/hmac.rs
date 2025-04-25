//! Computation of HMAC-SHA256.
//!
//! HMAC-SHA256 is defined as
//!
//! HMAC(m) = H((key' xor opad) || H((key' xor ipad) || m))
//!
//! * H     - SHA256 hash function
//! * key'  - key padded with zero bytes to 64 bytes (we do not support longer
//!   keys)
//! * opad  - 64 bytes of 0x5c
//! * ipad  - 64 bytes of 0x36
//! * m     - message
//!
//! This implementation computes HMAC-SHA256 using intermediate results
//! `outer_partial` and `inner_local`. Then HMAC(m) = H(outer_partial ||
//! inner_local)
//!
//! * `outer_partial`   - key' xor opad
//! * `inner_local`     - H((key' xor ipad) || m)

use crate::{sha256::Sha256, PrfError};
use mpz_vm_core::{
    memory::{
        binary::{Binary, U32, U8},
        Array,
    },
    Vm,
};

/// Computes HMAC-SHA256.
#[derive(Debug)]
pub(crate) struct HmacSha256 {
    outer_partial: Array<U32, 8>,
    inner_local: Array<U8, 32>,
}

impl HmacSha256 {
    pub(crate) const IPAD: [u8; 64] = [0x36; 64];
    pub(crate) const OPAD: [u8; 64] = [0x5c; 64];

    /// Creates a new instance.
    ///
    /// # Arguments
    ///
    /// * `outer_partial` - (key' xor opad)
    /// * `inner_local` - H((key' xor ipad) || m)
    pub(crate) fn new(outer_partial: Array<U32, 8>, inner_local: Array<U8, 32>) -> Self {
        Self {
            outer_partial,
            inner_local,
        }
    }

    /// Adds the circuit to the [`Vm`] and returns the output.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine.
    pub(crate) fn alloc(self, vm: &mut dyn Vm<Binary>) -> Result<Array<U32, 8>, PrfError> {
        let inner_local = self.inner_local.into();

        let mut outer = Sha256::default();
        outer
            .set_state(self.outer_partial, 64)
            .update(inner_local)
            .add_padding(vm)?;

        outer.alloc(vm)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        convert_to_bytes,
        hmac::HmacSha256,
        sha256::sha256,
        test_utils::{compute_inner_local, compute_outer_partial, mock_vm},
    };
    use mpz_common::context::test_st_context;
    use mpz_vm_core::{
        memory::{
            binary::{U32, U8},
            Array, MemoryExt, ViewExt,
        },
        Execute,
    };

    #[test]
    fn test_hmac_reference() {
        let (inputs, references) = test_fixtures();

        for (input, &reference) in inputs.iter().zip(references.iter()) {
            let outer_partial = compute_outer_partial(input.0.clone());
            let inner_local = compute_inner_local(input.0.clone(), &input.1);

            let hmac = sha256(outer_partial, 64, &convert_to_bytes(inner_local));

            assert_eq!(convert_to_bytes(hmac), reference);
        }
    }

    #[tokio::test]
    async fn test_hmac_circuit() {
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut leader, mut follower) = mock_vm();

        let (inputs, references) = test_fixtures();
        for (input, &reference) in inputs.iter().zip(references.iter()) {
            let outer_partial = compute_outer_partial(input.0.clone());
            let inner_local = compute_inner_local(input.0.clone(), &input.1);

            let outer_partial_leader: Array<U32, 8> = leader.alloc().unwrap();
            leader.mark_public(outer_partial_leader).unwrap();
            leader.assign(outer_partial_leader, outer_partial).unwrap();
            leader.commit(outer_partial_leader).unwrap();

            let inner_local_leader: Array<U8, 32> = leader.alloc().unwrap();
            leader.mark_public(inner_local_leader).unwrap();
            leader
                .assign(inner_local_leader, convert_to_bytes(inner_local))
                .unwrap();
            leader.commit(inner_local_leader).unwrap();

            let hmac_leader = HmacSha256::new(outer_partial_leader, inner_local_leader)
                .alloc(&mut leader)
                .unwrap();
            let hmac_leader = leader.decode(hmac_leader).unwrap();

            let outer_partial_follower: Array<U32, 8> = follower.alloc().unwrap();
            follower.mark_public(outer_partial_follower).unwrap();
            follower
                .assign(outer_partial_follower, outer_partial)
                .unwrap();
            follower.commit(outer_partial_follower).unwrap();

            let inner_local_follower: Array<U8, 32> = follower.alloc().unwrap();
            follower.mark_public(inner_local_follower).unwrap();
            follower
                .assign(inner_local_follower, convert_to_bytes(inner_local))
                .unwrap();
            follower.commit(inner_local_follower).unwrap();

            let hmac_follower = HmacSha256::new(outer_partial_follower, inner_local_follower)
                .alloc(&mut follower)
                .unwrap();
            let hmac_follower = follower.decode(hmac_follower).unwrap();

            let (hmac_leader, hmac_follower) = tokio::try_join!(
                async {
                    leader.execute_all(&mut ctx_a).await.unwrap();
                    hmac_leader.await
                },
                async {
                    follower.execute_all(&mut ctx_b).await.unwrap();
                    hmac_follower.await
                }
            )
            .unwrap();

            assert_eq!(hmac_leader, hmac_follower);
            assert_eq!(convert_to_bytes(hmac_leader), reference);
        }
    }

    #[allow(clippy::type_complexity)]
    fn test_fixtures() -> (Vec<(Vec<u8>, Vec<u8>)>, Vec<[u8; 32]>) {
        let test_vectors: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (
                hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
                hex::decode("4869205468657265").unwrap(),
            ),
            (
                hex::decode("4a656665").unwrap(),
                hex::decode("7768617420646f2079612077616e7420666f72206e6f7468696e673f").unwrap(),
            ),
        ];
        let expected: Vec<[u8; 32]> = vec![
            hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
                .unwrap()
                .try_into()
                .unwrap(),
        ];

        (test_vectors, expected)
    }
}
