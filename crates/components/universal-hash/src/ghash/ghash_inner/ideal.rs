//! Ideal GHASH functionality.

use async_trait::async_trait;
use ghash_rc::{
    universal_hash::{KeyInit, UniversalHash as UniversalHashReference},
    GHash,
};
use mpz_common::{
    ideal::{ideal_f2p, Alice, Bob},
    Context,
};

use crate::{UniversalHash, UniversalHashError};

/// An ideal GHASH functionality.
#[derive(Debug)]
pub struct IdealGhash<Ctx> {
    role: Role,
    context: Ctx,
}

#[derive(Debug)]
enum Role {
    Alice(Alice<GHash>),
    Bob(Bob<GHash>),
}

#[async_trait]
impl<Ctx: Context> UniversalHash for IdealGhash<Ctx> {
    async fn set_key(&mut self, key: Vec<u8>) -> Result<(), UniversalHashError> {
        match &mut self.role {
            Role::Alice(alice) => {
                alice
                    .call(
                        &mut self.context,
                        key,
                        |ghash, alice_key, bob_key: Vec<u8>| {
                            let key = alice_key
                                .into_iter()
                                .zip(bob_key)
                                .map(|(a, b)| a ^ b)
                                .collect::<Vec<_>>();
                            *ghash = GHash::new_from_slice(&key).unwrap();
                            ((), ())
                        },
                    )
                    .await
            }
            Role::Bob(bob) => {
                bob.call(
                    &mut self.context,
                    key,
                    |ghash, alice_key: Vec<u8>, bob_key| {
                        let key = alice_key
                            .into_iter()
                            .zip(bob_key)
                            .map(|(a, b)| a ^ b)
                            .collect::<Vec<_>>();
                        *ghash = GHash::new_from_slice(&key).unwrap();
                        ((), ())
                    },
                )
                .await
            }
        }

        Ok(())
    }

    async fn setup(&mut self) -> Result<(), UniversalHashError> {
        Ok(())
    }

    async fn preprocess(&mut self) -> Result<(), UniversalHashError> {
        Ok(())
    }

    async fn finalize(&mut self, input: Vec<u8>) -> Result<Vec<u8>, UniversalHashError> {
        Ok(match &mut self.role {
            Role::Alice(alice) => {
                alice
                    .call(
                        &mut self.context,
                        input,
                        |ghash, alice_input, bob_input: Vec<u8>| {
                            assert_eq!(&alice_input, &bob_input);

                            let mut ghash = ghash.clone();
                            ghash.update_padded(&alice_input);
                            let output = ghash.finalize().to_vec();

                            let output_bob = vec![0; output.len()];
                            let output_alice: Vec<u8> = output
                                .iter()
                                .zip(output_bob.iter().copied())
                                .map(|(o, b)| o ^ b)
                                .collect();
                            (output_alice, output_bob)
                        },
                    )
                    .await
            }
            Role::Bob(bob) => {
                bob.call(
                    &mut self.context,
                    input,
                    |ghash, alice_input: Vec<u8>, bob_input| {
                        assert_eq!(&alice_input, &bob_input);

                        let mut ghash = ghash.clone();
                        ghash.update_padded(&alice_input);
                        let output = ghash.finalize();

                        let output_bob = vec![0; output.len()];
                        let output_alice: Vec<u8> = output
                            .iter()
                            .zip(output_bob.iter().copied())
                            .map(|(o, b)| o ^ b)
                            .collect();
                        (output_alice, output_bob)
                    },
                )
                .await
            }
        })
    }
}

/// Creates an ideal GHASH pair.
pub fn ideal_ghash<Ctx: Context>(
    context_alice: Ctx,
    context_bob: Ctx,
) -> (IdealGhash<Ctx>, IdealGhash<Ctx>) {
    let (alice, bob) = ideal_f2p(GHash::new_from_slice(&[0u8; 16]).unwrap());
    (
        IdealGhash {
            role: Role::Alice(alice),
            context: context_alice,
        },
        IdealGhash {
            role: Role::Bob(bob),
            context: context_bob,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_common::executor::test_st_executor;

    #[tokio::test]
    async fn test_ideal_ghash() {
        let (ctx_a, ctx_b) = test_st_executor(8);
        let (mut alice, mut bob) = ideal_ghash(ctx_a, ctx_b);

        let alice_key = vec![42u8; 16];
        let bob_key = vec![69u8; 16];
        let key = alice_key
            .iter()
            .zip(bob_key.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<_>>();

        tokio::try_join!(
            alice.set_key(alice_key.clone()),
            bob.set_key(bob_key.clone())
        )
        .unwrap();

        let input = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        let (output_a, output_b) =
            tokio::try_join!(alice.finalize(input.clone()), bob.finalize(input.clone())).unwrap();

        let mut ghash = GHash::new_from_slice(&key).unwrap();
        ghash.update_padded(&input);
        let expected_output = ghash.finalize();

        let output: Vec<u8> = output_a.iter().zip(output_b).map(|(a, b)| a ^ b).collect();
        assert_eq!(output, expected_output.to_vec());
    }
}
