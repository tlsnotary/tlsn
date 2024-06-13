//! This module implements the key exchange logic.

use async_trait::async_trait;
use mpz_common::{scoped_futures::ScopedFutureExt, Allocate, Context, Preprocess};
use mpz_garble::{value::ValueRef, Decode, Execute, Load, Memory};

use mpz_fields::{p256::P256, Field};
use mpz_share_conversion::{ShareConversionError, ShareConvert};
use p256::{EncodedPoint, PublicKey, SecretKey};
use serio::{stream::IoStreamExt, SinkExt};
use std::fmt::Debug;
use tracing::{debug, instrument};

use crate::{
    circuit::build_pms_circuit,
    config::{KeyExchangeConfig, Role},
    error::ErrorKind,
    point_addition::derive_x_coord_share,
    KeyExchange, KeyExchangeError, Pms,
};

#[derive(Debug)]
enum State {
    Initialized,
    Setup {
        share_a0: ValueRef,
        share_b0: ValueRef,
        share_a1: ValueRef,
        share_b1: ValueRef,
        pms_0: ValueRef,
        pms_1: ValueRef,
        eq: ValueRef,
    },
    Preprocessed {
        share_a0: ValueRef,
        share_b0: ValueRef,
        share_a1: ValueRef,
        share_b1: ValueRef,
        pms_0: ValueRef,
        pms_1: ValueRef,
        eq: ValueRef,
    },
    Complete,
    Error,
}

impl State {
    fn is_preprocessed(&self) -> bool {
        matches!(self, Self::Preprocessed { .. })
    }

    fn take(&mut self) -> Self {
        std::mem::replace(self, Self::Error)
    }
}

/// An MPC key exchange protocol.
///
/// Can be either a leader or a follower depending on the `role` field in [`KeyExchangeConfig`].
#[derive(Debug)]
pub struct MpcKeyExchange<Ctx, C0, C1, E> {
    ctx: Ctx,
    /// Share conversion protocol 0.
    converter_0: C0,
    /// Share conversion protocol 1.
    converter_1: C1,
    /// MPC executor.
    executor: E,
    /// The private key of the party behind this instance, either follower or leader.
    private_key: Option<SecretKey>,
    /// The public key of the server.
    server_key: Option<PublicKey>,
    /// The config used for the key exchange protocol.
    config: KeyExchangeConfig,
    /// The state of the protocol.
    state: State,
}

impl<Ctx, C0, C1, E> MpcKeyExchange<Ctx, C0, C1, E> {
    /// Creates a new [`MpcKeyExchange`].
    ///
    /// # Arguments
    ///
    /// * `config` - Key exchange configuration.
    /// * `ctx` - Thread context.
    /// * `converter_0` - Share conversion protocol instance 0.
    /// * `converter_1` - Share conversion protocol instance 1.
    /// * `executor` - MPC executor.
    pub fn new(
        config: KeyExchangeConfig,
        ctx: Ctx,
        converter_0: C0,
        converter_1: C1,
        executor: E,
    ) -> Self {
        Self {
            ctx,
            converter_0,
            converter_1,
            executor,
            private_key: None,
            server_key: None,
            config,
            state: State::Initialized,
        }
    }
}

impl<Ctx, C0, C1, E> MpcKeyExchange<Ctx, C0, C1, E>
where
    Ctx: Context,
    E: Execute + Load + Memory + Decode + Send,
    C0: ShareConvert<Ctx, P256> + Send,
    C1: ShareConvert<Ctx, P256> + Send,
{
    async fn compute_pms_shares(
        &mut self,
        server_key: PublicKey,
        private_key: SecretKey,
    ) -> Result<(P256, P256), KeyExchangeError> {
        compute_pms_shares(
            &mut self.ctx,
            *self.config.role(),
            &mut self.converter_0,
            &mut self.converter_1,
            server_key,
            private_key,
        )
        .await
    }

    // Computes the PMS using both parties' shares, performing an equality check
    // to ensure the shares are equal.
    async fn compute_pms_with(
        &mut self,
        share_0: P256,
        share_1: P256,
    ) -> Result<Pms, KeyExchangeError> {
        let State::Preprocessed {
            share_a0,
            share_b0,
            share_a1,
            share_b1,
            pms_0,
            pms_1,
            eq,
        } = self.state.take()
        else {
            return Err(KeyExchangeError::state("not in preprocessed state"));
        };

        let share_0_bytes: [u8; 32] = share_0
            .to_be_bytes()
            .try_into()
            .expect("pms share is 32 bytes");
        let share_1_bytes: [u8; 32] = share_1
            .to_be_bytes()
            .try_into()
            .expect("pms share is 32 bytes");

        match self.config.role() {
            Role::Leader => {
                self.executor.assign(&share_a0, share_0_bytes)?;
                self.executor.assign(&share_a1, share_1_bytes)?;
            }
            Role::Follower => {
                self.executor.assign(&share_b0, share_0_bytes)?;
                self.executor.assign(&share_b1, share_1_bytes)?;
            }
        }

        self.executor
            .execute(
                build_pms_circuit(),
                &[share_a0, share_b0, share_a1, share_b1],
                &[pms_0.clone(), pms_1, eq.clone()],
            )
            .await?;

        let eq: [u8; 32] = self
            .executor
            .decode(&[eq])
            .await?
            .pop()
            .expect("output 0 is eq")
            .try_into()
            .expect("eq is 32 bytes");

        // Eq should be all zeros if pms_1 == pms_2.
        if eq != [0u8; 32] {
            return Err(KeyExchangeError::new(
                ErrorKind::ShareConversion,
                "PMS values not equal",
            ));
        }

        // Both parties use pms_0 as the pre-master secret.
        Ok(Pms::new(pms_0))
    }
}

#[async_trait]
impl<Ctx, C0, C1, E> KeyExchange for MpcKeyExchange<Ctx, C0, C1, E>
where
    Ctx: Context,
    E: Execute + Load + Memory + Decode + Send,
    C0: Allocate + Preprocess<Ctx, Error = ShareConversionError> + ShareConvert<Ctx, P256> + Send,
    C1: Allocate + Preprocess<Ctx, Error = ShareConversionError> + ShareConvert<Ctx, P256> + Send,
{
    fn server_key(&self) -> Option<PublicKey> {
        self.server_key
    }

    async fn set_server_key(&mut self, server_key: PublicKey) -> Result<(), KeyExchangeError> {
        let Role::Leader = self.config.role() else {
            return Err(KeyExchangeError::role("follower cannot set server key"));
        };

        // Send server public key to follower.
        self.ctx.io_mut().send(server_key).await?;

        self.server_key = Some(server_key);

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn setup(&mut self) -> Result<Pms, KeyExchangeError> {
        let State::Initialized = self.state.take() else {
            return Err(KeyExchangeError::state("not in initialized state"));
        };

        // 2 A2M, 1 M2A.
        self.converter_0.alloc(3);
        self.converter_1.alloc(3);

        let (share_a0, share_b0, share_a1, share_b1) = match self.config.role() {
            Role::Leader => {
                let share_a0 = self
                    .executor
                    .new_private_input::<[u8; 32]>("pms/share_a0")?;
                let share_b0 = self.executor.new_blind_input::<[u8; 32]>("pms/share_b0")?;
                let share_a1 = self
                    .executor
                    .new_private_input::<[u8; 32]>("pms/share_a1")?;
                let share_b1 = self.executor.new_blind_input::<[u8; 32]>("pms/share_b1")?;

                (share_a0, share_b0, share_a1, share_b1)
            }
            Role::Follower => {
                let share_a0 = self.executor.new_blind_input::<[u8; 32]>("pms/share_a0")?;
                let share_b0 = self
                    .executor
                    .new_private_input::<[u8; 32]>("pms/share_b0")?;
                let share_a1 = self.executor.new_blind_input::<[u8; 32]>("pms/share_a1")?;
                let share_b1 = self
                    .executor
                    .new_private_input::<[u8; 32]>("pms/share_b1")?;

                (share_a0, share_b0, share_a1, share_b1)
            }
        };

        let pms_0 = self.executor.new_output::<[u8; 32]>("pms_0")?;
        let pms_1 = self.executor.new_output::<[u8; 32]>("pms_1")?;
        let eq = self.executor.new_output::<[u8; 32]>("eq")?;

        self.state = State::Setup {
            share_a0,
            share_b0,
            share_a1,
            share_b1,
            pms_0: pms_0.clone(),
            pms_1,
            eq,
        };

        Ok(Pms::new(pms_0))
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn preprocess(&mut self) -> Result<(), KeyExchangeError> {
        let State::Setup {
            share_a0,
            share_b0,
            share_a1,
            share_b1,
            pms_0,
            pms_1,
            eq,
        } = self.state.take()
        else {
            return Err(KeyExchangeError::state("not in setup state"));
        };

        // Preprocess share conversion and garbled circuits concurrently.
        futures::try_join!(
            async {
                self.ctx
                    .try_join(
                        |ctx| self.converter_0.preprocess(ctx).scope_boxed(),
                        |ctx| self.converter_1.preprocess(ctx).scope_boxed(),
                    )
                    .await??;

                Ok::<_, KeyExchangeError>(())
            },
            async {
                self.executor
                    .load(
                        build_pms_circuit(),
                        &[
                            share_a0.clone(),
                            share_b0.clone(),
                            share_a1.clone(),
                            share_b1.clone(),
                        ],
                        &[pms_0.clone(), pms_1.clone(), eq.clone()],
                    )
                    .await?;

                Ok::<_, KeyExchangeError>(())
            }
        )?;

        // Follower can forward their key share immediately.
        if let Role::Follower = self.config.role() {
            let private_key = self
                .private_key
                .get_or_insert_with(|| SecretKey::random(&mut rand::rngs::OsRng));

            self.ctx.io_mut().send(private_key.public_key()).await?;

            debug!("sent public key share to leader");
        }

        self.state = State::Preprocessed {
            share_a0,
            share_b0,
            share_a1,
            share_b1,
            pms_0,
            pms_1,
            eq,
        };

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn client_key(&mut self) -> Result<PublicKey, KeyExchangeError> {
        if let Role::Leader = self.config.role() {
            let private_key = self
                .private_key
                .get_or_insert_with(|| SecretKey::random(&mut rand::rngs::OsRng));
            let public_key = private_key.public_key();

            // Receive public key share from follower.
            let follower_public_key: PublicKey = self.ctx.io_mut().expect_next().await?;

            debug!("received public key share from follower");

            // Combine public keys.
            let client_public_key = PublicKey::from_affine(
                (public_key.to_projective() + follower_public_key.to_projective()).to_affine(),
            )?;

            Ok(client_public_key)
        } else {
            Err(KeyExchangeError::role("follower does not learn client key"))
        }
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn compute_pms(&mut self) -> Result<Pms, KeyExchangeError> {
        if !self.state.is_preprocessed() {
            return Err(KeyExchangeError::state("not in preprocessed state"));
        }

        let server_key = match self.config.role() {
            Role::Leader => self
                .server_key
                .ok_or_else(|| KeyExchangeError::state("server public key not set"))?,
            Role::Follower => {
                // Receive server public key from leader.
                let server_key = self.ctx.io_mut().expect_next().await?;

                self.server_key = Some(server_key);

                server_key
            }
        };

        let private_key = self
            .private_key
            .take()
            .ok_or(KeyExchangeError::state("private key not set"))?;

        let (pms_share_0, pms_share_1) = self.compute_pms_shares(server_key, private_key).await?;
        let pms = self.compute_pms_with(pms_share_0, pms_share_1).await?;

        self.state = State::Complete;

        Ok(pms)
    }
}

async fn compute_pms_shares<
    Ctx: Context,
    C0: ShareConvert<Ctx, P256> + Send,
    C1: ShareConvert<Ctx, P256> + Send,
>(
    ctx: &mut Ctx,
    role: Role,
    converter_0: &mut C0,
    converter_1: &mut C1,
    server_key: PublicKey,
    private_key: SecretKey,
) -> Result<(P256, P256), KeyExchangeError> {
    // Compute the leader's/follower's share of the pre-master secret.
    //
    // We need to mimic the [diffie-hellman](p256::ecdh::diffie_hellman) function without the
    // [SharedSecret](p256::ecdh::SharedSecret) wrapper, because this makes it harder to get
    // the result as an EC curve point.
    let shared_secret = {
        let public_projective = server_key.to_projective();
        (public_projective * private_key.to_nonzero_scalar().as_ref()).to_affine()
    };

    let encoded_point = EncodedPoint::from(PublicKey::from_affine(shared_secret)?);

    let (pms_share_0, pms_share_1) = ctx
        .try_join(
            |ctx| {
                async { derive_x_coord_share(role, ctx, converter_0, encoded_point).await }
                    .scope_boxed()
            },
            |ctx| {
                async { derive_x_coord_share(role, ctx, converter_1, encoded_point).await }
                    .scope_boxed()
            },
        )
        .await??;

    Ok((pms_share_0, pms_share_1))
}

#[cfg(test)]
mod tests {
    use super::*;

    use mpz_common::executor::{test_st_executor, STExecutor};
    use mpz_garble::protocol::deap::mock::{create_mock_deap_vm, MockFollower, MockLeader};
    use mpz_share_conversion::ideal::{ideal_share_converter, IdealShareConverter};
    use p256::{NonZeroScalar, PublicKey, SecretKey};
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;
    use serio::channel::MemoryDuplex;

    fn create_pair() -> (
        MpcKeyExchange<
            STExecutor<MemoryDuplex>,
            IdealShareConverter,
            IdealShareConverter,
            MockLeader,
        >,
        MpcKeyExchange<
            STExecutor<MemoryDuplex>,
            IdealShareConverter,
            IdealShareConverter,
            MockFollower,
        >,
    ) {
        let (leader_ctx, follower_ctx) = test_st_executor(8);
        let (leader_converter_0, follower_converter_0) = ideal_share_converter();
        let (follower_converter_1, leader_converter_1) = ideal_share_converter();
        let (leader_vm, follower_vm) = create_mock_deap_vm();

        let leader = MpcKeyExchange::new(
            KeyExchangeConfig::builder()
                .role(Role::Leader)
                .build()
                .unwrap(),
            leader_ctx,
            leader_converter_0,
            leader_converter_1,
            leader_vm,
        );

        let follower = MpcKeyExchange::new(
            KeyExchangeConfig::builder()
                .role(Role::Follower)
                .build()
                .unwrap(),
            follower_ctx,
            follower_converter_0,
            follower_converter_1,
            follower_vm,
        );

        (leader, follower)
    }

    #[tokio::test]
    async fn test_key_exchange() {
        let mut rng = ChaCha12Rng::from_seed([0_u8; 32]);

        let leader_private_key = SecretKey::random(&mut rng);
        let follower_private_key = SecretKey::random(&mut rng);
        let server_public_key = PublicKey::from_secret_scalar(&NonZeroScalar::random(&mut rng));

        let (mut leader, mut follower) = create_pair();

        leader.private_key = Some(leader_private_key.clone());
        follower.private_key = Some(follower_private_key.clone());

        tokio::try_join!(leader.setup(), follower.setup()).unwrap();
        tokio::try_join!(leader.preprocess(), follower.preprocess()).unwrap();

        let client_public_key = leader.client_key().await.unwrap();
        leader.set_server_key(server_public_key).await.unwrap();

        let expected_client_public_key = PublicKey::from_affine(
            (leader_private_key.public_key().to_projective()
                + follower_private_key.public_key().to_projective())
            .to_affine(),
        )
        .unwrap();

        assert_eq!(client_public_key, expected_client_public_key);
    }

    #[tokio::test]
    async fn test_compute_pms() {
        let mut rng = ChaCha12Rng::from_seed([0_u8; 32]);

        let leader_private_key = SecretKey::random(&mut rng);
        let follower_private_key = SecretKey::random(&mut rng);
        let server_private_key = NonZeroScalar::random(&mut rng);
        let server_public_key = PublicKey::from_secret_scalar(&server_private_key);

        let (mut leader, mut follower) = create_pair();

        leader.private_key = Some(leader_private_key);
        follower.private_key = Some(follower_private_key);

        tokio::try_join!(leader.setup(), follower.setup()).unwrap();
        tokio::try_join!(leader.preprocess(), follower.preprocess()).unwrap();

        leader.set_server_key(server_public_key).await.unwrap();

        let (_leader_pms, _follower_pms) =
            tokio::try_join!(leader.compute_pms(), follower.compute_pms()).unwrap();

        assert_eq!(leader.server_key.unwrap(), server_public_key);
        assert_eq!(follower.server_key.unwrap(), server_public_key);
    }

    #[tokio::test]
    async fn test_compute_pms_shares() {
        let mut rng = ChaCha12Rng::from_seed([0_u8; 32]);
        let (mut ctx_leader, mut ctx_follower) = test_st_executor(8);
        let (mut leader_converter_0, mut follower_converter_0) = ideal_share_converter();
        let (mut follower_converter_1, mut leader_converter_1) = ideal_share_converter();

        let leader_private_key = SecretKey::random(&mut rng);
        let follower_private_key = SecretKey::random(&mut rng);
        let server_private_key = NonZeroScalar::random(&mut rng);
        let server_public_key = PublicKey::from_secret_scalar(&server_private_key);

        let client_public_key = PublicKey::from_affine(
            (leader_private_key.public_key().to_projective()
                + follower_private_key.public_key().to_projective())
            .to_affine(),
        )
        .unwrap();

        let ((leader_share_0, leader_share_1), (follower_share_0, follower_share_1)) =
            tokio::try_join!(
                compute_pms_shares(
                    &mut ctx_leader,
                    Role::Leader,
                    &mut leader_converter_0,
                    &mut leader_converter_1,
                    server_public_key,
                    leader_private_key
                ),
                compute_pms_shares(
                    &mut ctx_follower,
                    Role::Follower,
                    &mut follower_converter_0,
                    &mut follower_converter_1,
                    server_public_key,
                    follower_private_key
                )
            )
            .unwrap();

        let expected_ecdh_x =
            p256::ecdh::diffie_hellman(server_private_key, client_public_key.as_affine());

        assert_eq!(
            (leader_share_0 + follower_share_0).to_be_bytes(),
            expected_ecdh_x.raw_secret_bytes().to_vec()
        );
        assert_eq!(
            (leader_share_1 + follower_share_1).to_be_bytes(),
            expected_ecdh_x.raw_secret_bytes().to_vec()
        );

        assert_ne!(leader_share_0, follower_share_0);
        assert_ne!(leader_share_1, follower_share_1);
    }

    #[tokio::test]
    async fn test_compute_pms_fail() {
        let mut rng = ChaCha12Rng::from_seed([0_u8; 32]);

        let leader_private_key = SecretKey::random(&mut rng);
        let follower_private_key = SecretKey::random(&mut rng);
        let server_private_key = NonZeroScalar::random(&mut rng);
        let server_public_key = PublicKey::from_secret_scalar(&server_private_key);

        let (mut leader, mut follower) = create_pair();

        leader.private_key = Some(leader_private_key.clone());
        follower.private_key = Some(follower_private_key.clone());

        tokio::try_join!(leader.setup(), follower.setup()).unwrap();
        tokio::try_join!(leader.preprocess(), follower.preprocess()).unwrap();

        leader.set_server_key(server_public_key).await.unwrap();

        let ((mut share_a0, share_a1), (share_b0, share_b1)) = tokio::try_join!(
            leader.compute_pms_shares(server_public_key, leader_private_key),
            follower.compute_pms_shares(server_public_key, follower_private_key)
        )
        .unwrap();

        share_a0 = share_a0 + P256::one();

        let (leader_res, follower_res) = tokio::join!(
            leader.compute_pms_with(share_a0, share_a1),
            follower.compute_pms_with(share_b0, share_b1)
        );

        let leader_err = leader_res.unwrap_err();
        let follower_err = follower_res.unwrap_err();

        assert!(matches!(leader_err.kind(), ErrorKind::ShareConversion));
        assert!(matches!(follower_err.kind(), ErrorKind::ShareConversion));
    }
}
