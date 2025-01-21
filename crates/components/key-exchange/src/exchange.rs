//! This module implements the key exchange logic.

use std::{fmt::Debug, sync::Arc};

use async_trait::async_trait;
use p256::{EncodedPoint, PublicKey, SecretKey};
use serio::{sink::SinkExt, stream::IoStreamExt};
use tokio::sync::Mutex;
use tracing::instrument;

use mpz_common::{scoped_futures::ScopedFutureExt, Context, Flush};
use mpz_core::bitvec::BitVec;
use mpz_fields::{p256::P256, Field};
use mpz_memory_core::{
    binary::{Binary, U8},
    Array, DecodeFutureTyped, Memory, MemoryExt, View, ViewExt,
};
use mpz_share_conversion::{AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConvert};
use mpz_vm_core::{CallBuilder, Vm, VmExt};

use crate::{
    circuit::build_pms_circuit,
    config::{KeyExchangeConfig, Role},
    point_addition::derive_x_coord_share,
    KeyExchange, KeyExchangeError, Pms,
};

#[derive(Debug)]
enum State {
    Initialized,
    Setup {
        share_a0: Array<U8, 32>,
        share_b0: Array<U8, 32>,
        share_a1: Array<U8, 32>,
        share_b1: Array<U8, 32>,
        eq: Array<U8, 32>,
    },
    FollowerKey {
        follower_key: PublicKey,
        share_a0: Array<U8, 32>,
        share_b0: Array<U8, 32>,
        share_a1: Array<U8, 32>,
        share_b1: Array<U8, 32>,
        eq: Array<U8, 32>,
    },
    ComputedECShares {
        share_a0: Array<U8, 32>,
        share_b0: Array<U8, 32>,
        share_a1: Array<U8, 32>,
        share_b1: Array<U8, 32>,
        eq: Array<U8, 32>,
        pms_0: P256,
        pms_1: P256,
    },
    EqualityCheck {
        eq: DecodeFutureTyped<BitVec, [u8; 32]>,
    },
    Complete,
    Error,
}

impl State {
    fn take(&mut self) -> Self {
        std::mem::replace(self, Self::Error)
    }
}

/// An MPC key exchange protocol.
///
/// Can be either a leader or a follower depending on the `role` field in
/// [`KeyExchangeConfig`].
#[derive(Debug)]
pub struct MpcKeyExchange<C0, C1> {
    /// Share conversion protocol 0.
    converter_0: Arc<Mutex<C0>>,
    /// Share conversion protocol 1.
    converter_1: Arc<Mutex<C1>>,
    /// The config used for the key exchange protocol.
    config: KeyExchangeConfig,
    /// The state of the protocol.
    state: State,
    /// This party's private key.
    private_key: SecretKey,
    /// Server's public key.
    server_key: Option<PublicKey>,
}

impl<C0, C1> MpcKeyExchange<C0, C1> {
    /// Creates a new [`MpcKeyExchange`].
    ///
    /// # Arguments
    ///
    /// * `config` - Key exchange configuration.
    /// * `converter_0` - Share conversion protocol instance 0.
    /// * `converter_1` - Share conversion protocol instance 1.
    pub fn new(config: KeyExchangeConfig, converter_0: C0, converter_1: C1) -> Self {
        let private_key = SecretKey::random(&mut rand::rngs::OsRng);

        Self {
            converter_0: Arc::new(Mutex::new(converter_0)),
            converter_1: Arc::new(Mutex::new(converter_1)),
            config,
            state: State::Initialized,
            private_key,
            server_key: None,
        }
    }
}

impl<C0, C1> KeyExchange for MpcKeyExchange<C0, C1>
where
    C0: ShareConvert<P256> + Send,
    C1: ShareConvert<P256> + Send,
{
    fn alloc(&mut self) -> Result<(), KeyExchangeError> {
        let mut converter_0 = self.converter_0.try_lock().unwrap();
        let mut converter_1 = self.converter_1.try_lock().unwrap();

        // 2 A2M, 1 M2A.
        MultiplicativeToAdditive::alloc(&mut *converter_0, 1)
            .map_err(KeyExchangeError::share_conversion)?;
        MultiplicativeToAdditive::alloc(&mut *converter_1, 1)
            .map_err(KeyExchangeError::share_conversion)?;

        AdditiveToMultiplicative::alloc(&mut *converter_0, 2)
            .map_err(KeyExchangeError::share_conversion)?;
        AdditiveToMultiplicative::alloc(&mut *converter_1, 2)
            .map_err(KeyExchangeError::share_conversion)?;

        Ok(())
    }

    fn set_server_key(&mut self, server_key: PublicKey) -> Result<(), KeyExchangeError> {
        let Role::Leader = self.config.role() else {
            return Err(KeyExchangeError::role("follower cannot set server key"));
        };

        self.server_key = Some(server_key);

        Ok(())
    }

    fn server_key(&self) -> Option<PublicKey> {
        self.server_key
    }

    #[instrument(level = "debug", skip_all, err)]
    fn client_key(&self) -> Result<PublicKey, KeyExchangeError> {
        let Role::Leader = self.config.role() else {
            return Err(KeyExchangeError::role("follower does not learn client key"));
        };

        let State::FollowerKey { follower_key, .. } = &self.state else {
            return Err(KeyExchangeError::state(
                "leader should be in FollowerKey state for returning the client key",
            ));
        };

        let public_key = self.private_key.public_key();

        // Combine public keys.
        let client_public_key = PublicKey::from_affine(
            (public_key.to_projective() + follower_key.to_projective()).to_affine(),
        )?;

        Ok(client_public_key)
    }

    #[instrument(level = "debug", skip_all, err)]
    fn setup<V>(&mut self, vm: &mut V) -> Result<Pms, KeyExchangeError>
    where
        V: Vm<Binary> + Memory<Binary> + View<Binary>,
    {
        let State::Initialized = self.state.take() else {
            return Err(KeyExchangeError::state(
                "should be in Initialized state to call setup",
            ));
        };

        let (share_a0, share_b0, share_a1, share_b1) = match self.config.role() {
            Role::Leader => {
                let share_a0: Array<U8, 32> = vm.alloc().map_err(KeyExchangeError::vm)?;
                vm.mark_private(share_a0).map_err(KeyExchangeError::vm)?;

                let share_b0: Array<U8, 32> = vm.alloc().map_err(KeyExchangeError::vm)?;
                vm.mark_blind(share_b0).map_err(KeyExchangeError::vm)?;

                let share_a1: Array<U8, 32> = vm.alloc().map_err(KeyExchangeError::vm)?;
                vm.mark_private(share_a1).map_err(KeyExchangeError::vm)?;

                let share_b1: Array<U8, 32> = vm.alloc().map_err(KeyExchangeError::vm)?;
                vm.mark_blind(share_b1).map_err(KeyExchangeError::vm)?;

                (share_a0, share_b0, share_a1, share_b1)
            }
            Role::Follower => {
                let share_a0: Array<U8, 32> = vm.alloc().map_err(KeyExchangeError::vm)?;
                vm.mark_blind(share_a0).map_err(KeyExchangeError::vm)?;

                let share_b0: Array<U8, 32> = vm.alloc().map_err(KeyExchangeError::vm)?;
                vm.mark_private(share_b0).map_err(KeyExchangeError::vm)?;

                let share_a1: Array<U8, 32> = vm.alloc().map_err(KeyExchangeError::vm)?;
                vm.mark_blind(share_a1).map_err(KeyExchangeError::vm)?;

                let share_b1: Array<U8, 32> = vm.alloc().map_err(KeyExchangeError::vm)?;
                vm.mark_private(share_b1).map_err(KeyExchangeError::vm)?;

                (share_a0, share_b0, share_a1, share_b1)
            }
        };

        let pms_circuit = build_pms_circuit();
        let pms_call = CallBuilder::new(pms_circuit)
            .arg(share_a0)
            .arg(share_b0)
            .arg(share_a1)
            .arg(share_b1)
            .build()
            .map_err(KeyExchangeError::vm)?;

        let (pms, _, eq): (Array<U8, 32>, Array<U8, 32>, Array<U8, 32>) =
            vm.call(pms_call).map_err(KeyExchangeError::vm)?;

        self.state = State::Setup {
            share_a0,
            share_b0,
            share_a1,
            share_b1,
            eq,
        };

        Ok(Pms::new(pms))
    }

    #[instrument(level = "debug", skip_all, err)]
    fn compute_pms<V>(&mut self, vm: &mut V) -> Result<(), KeyExchangeError>
    where
        V: Vm<Binary> + Memory<Binary> + View<Binary>,
    {
        let State::ComputedECShares {
            share_a0,
            share_b0,
            share_a1,
            share_b1,
            eq,
            pms_0,
            pms_1,
            ..
        } = std::mem::replace(&mut self.state, State::Error)
        else {
            return Err(KeyExchangeError::state(
                "should be in ComputedECShares state to compute pms",
            ));
        };

        let share_0_bytes: [u8; 32] = pms_0
            .to_be_bytes()
            .try_into()
            .expect("pms share is 32 bytes");
        let share_1_bytes: [u8; 32] = pms_1
            .to_be_bytes()
            .try_into()
            .expect("pms share is 32 bytes");

        match self.config.role() {
            Role::Leader => {
                vm.assign(share_a0, share_0_bytes)
                    .map_err(KeyExchangeError::vm)?;
                vm.commit(share_a0).map_err(KeyExchangeError::vm)?;

                vm.assign(share_a1, share_1_bytes)
                    .map_err(KeyExchangeError::vm)?;
                vm.commit(share_a1).map_err(KeyExchangeError::vm)?;

                vm.commit(share_b0).map_err(KeyExchangeError::vm)?;
                vm.commit(share_b1).map_err(KeyExchangeError::vm)?;
            }
            Role::Follower => {
                vm.assign(share_b0, share_0_bytes)
                    .map_err(KeyExchangeError::vm)?;
                vm.commit(share_b0).map_err(KeyExchangeError::vm)?;

                vm.assign(share_b1, share_1_bytes)
                    .map_err(KeyExchangeError::vm)?;
                vm.commit(share_b1).map_err(KeyExchangeError::vm)?;

                vm.commit(share_a0).map_err(KeyExchangeError::vm)?;
                vm.commit(share_a1).map_err(KeyExchangeError::vm)?;
            }
        }

        let eq = vm.decode(eq).map_err(KeyExchangeError::vm)?;

        self.state = State::EqualityCheck { eq };

        Ok(())
    }
}

#[async_trait]
impl<Ctx, C0, C1> Flush<Ctx> for MpcKeyExchange<C0, C1>
where
    Ctx: Context,
    C0: ShareConvert<P256> + Flush<Ctx> + Send + 'static,
    <C0 as AdditiveToMultiplicative<P256>>::Future: Send,
    <C0 as MultiplicativeToAdditive<P256>>::Future: Send,
    C1: ShareConvert<P256> + Flush<Ctx> + Send + 'static,
    <C1 as AdditiveToMultiplicative<P256>>::Future: Send,
    <C1 as MultiplicativeToAdditive<P256>>::Future: Send,
{
    type Error = KeyExchangeError;

    fn wants_flush(&self) -> bool {
        !matches!(
            self.state,
            State::Initialized | State::Complete | State::Error
        )
    }

    async fn flush(&mut self, ctx: &mut Ctx) -> Result<(), Self::Error> {
        if !self.wants_flush() {
            return Ok(());
        }

        self.state = match self.state.take() {
            State::Setup {
                share_a0,
                share_b0,
                share_a1,
                share_b1,
                eq,
            } => {
                let follower_key = match self.config.role() {
                    Role::Leader => ctx.io_mut().expect_next().await?,
                    Role::Follower => {
                        let follower_key = self.private_key.public_key();
                        ctx.io_mut().send(follower_key).await?;
                        follower_key
                    }
                };

                State::FollowerKey {
                    follower_key,
                    share_a0,
                    share_b0,
                    share_a1,
                    share_b1,
                    eq,
                }
            }
            State::FollowerKey {
                share_a0,
                share_b0,
                share_a1,
                share_b1,
                eq,
                ..
            } => {
                let server_key = match self.config.role() {
                    Role::Leader => {
                        let server_key = self
                            .server_key
                            .ok_or_else(|| KeyExchangeError::role("server key is not set"))?;

                        ctx.io_mut().send(server_key).await?;

                        server_key
                    }
                    Role::Follower => ctx.io_mut().expect_next().await?,
                };

                let (pms_0, pms_1) = compute_ec_shares(
                    ctx,
                    self.config.role(),
                    self.converter_0.clone(),
                    self.converter_1.clone(),
                    self.private_key.clone(),
                    server_key,
                )
                .await?;

                State::ComputedECShares {
                    share_a0,
                    share_b0,
                    share_a1,
                    share_b1,
                    eq,
                    pms_0,
                    pms_1,
                }
            }
            State::EqualityCheck { eq } => {
                let eq = eq.await.map_err(KeyExchangeError::vm)?;

                if eq != [0u8; 32] {
                    return Err(KeyExchangeError::share_conversion("PMS values not equal"));
                }

                State::Complete
            }
            state => state,
        };

        Ok(())
    }
}

async fn compute_ec_shares<Ctx, C0, C1>(
    ctx: &mut Ctx,
    role: Role,
    converter_0: Arc<Mutex<C0>>,
    converter_1: Arc<Mutex<C1>>,
    private_key: SecretKey,
    server_key: PublicKey,
) -> Result<(P256, P256), KeyExchangeError>
where
    Ctx: Context,
    C0: ShareConvert<P256> + Flush<Ctx> + Send + 'static,
    <C0 as AdditiveToMultiplicative<P256>>::Future: Send,
    <C0 as MultiplicativeToAdditive<P256>>::Future: Send,
    C1: ShareConvert<P256> + Flush<Ctx> + Send + 'static,
    <C1 as AdditiveToMultiplicative<P256>>::Future: Send,
    <C1 as MultiplicativeToAdditive<P256>>::Future: Send,
{
    // Compute the leader's/follower's share of the pre-master secret.
    //
    // We need to mimic the [diffie-hellman](p256::ecdh::diffie_hellman) function
    // without the [SharedSecret](p256::ecdh::SharedSecret) wrapper, because
    // this makes it harder to get the result as an EC curve point.
    let shared_secret = {
        let public_projective = server_key.to_projective();
        (public_projective * private_key.to_nonzero_scalar().as_ref()).to_affine()
    };

    let encoded_point = EncodedPoint::from(PublicKey::from_affine(shared_secret)?);

    let mut converter_0 = converter_0.try_lock_owned().unwrap();
    let mut converter_1 = converter_1.try_lock_owned().unwrap();
    let (pms_share_0, pms_share_1) = ctx
        .try_join(
            move |ctx| {
                async move { derive_x_coord_share(ctx, role, &mut *converter_0, encoded_point).await }
                    .scope_boxed()
            },
            move |ctx| {
                async move { derive_x_coord_share(ctx, role, &mut *converter_1, encoded_point).await }
                    .scope_boxed()
            },
        )
        .await??;

    Ok((pms_share_0, pms_share_1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorRepr;
    use mpz_common::executor::test_st_executor;
    use mpz_core::Block;
    use mpz_garble::protocol::semihonest::{Evaluator, Generator};
    use mpz_memory_core::correlated::Delta;
    use mpz_ot::ideal::cot::{ideal_cot, IdealCOTReceiver, IdealCOTSender};
    use mpz_share_conversion::ideal::{
        ideal_share_convert, IdealShareConvertReceiver, IdealShareConvertSender,
    };
    use mpz_vm_core::Execute;
    use p256::{NonZeroScalar, PublicKey, SecretKey};
    use rand::rngs::StdRng;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

    impl<C0, C1> MpcKeyExchange<C0, C1> {
        fn set_pms_0(&mut self, pms: P256) {
            let State::ComputedECShares { pms_0, .. } = &mut self.state else {
                panic!("Can only set private key in initialized state")
            };
            *pms_0 = pms;
        }
    }

    #[tokio::test]
    async fn test_key_exchange() {
        let mut rng = ChaCha12Rng::from_seed([0_u8; 32]);
        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let (mut gen, mut ev) = mock_vm();

        let leader_private_key = SecretKey::random(&mut rng);
        let follower_private_key = SecretKey::random(&mut rng);
        let server_public_key = PublicKey::from_secret_scalar(&NonZeroScalar::random(&mut rng));

        let (mut leader, mut follower) = create_pair();

        leader.alloc().unwrap();
        follower.alloc().unwrap();

        leader.private_key = leader_private_key.clone();
        follower.private_key = follower_private_key.clone();

        leader.setup(&mut gen).unwrap();
        follower.setup(&mut ev).unwrap();

        tokio::join!(
            async {
                leader.flush(&mut ctx_a).await.unwrap();

                let client_public_key = leader.client_key().unwrap();

                leader.set_server_key(server_public_key).unwrap();

                assert_eq!(leader.server_key().unwrap(), server_public_key);

                let expected_client_public_key = PublicKey::from_affine(
                    (leader_private_key.public_key().to_projective()
                        + follower_private_key.public_key().to_projective())
                    .to_affine(),
                )
                .unwrap();

                assert_eq!(client_public_key, expected_client_public_key);
                leader.flush(&mut ctx_a).await.unwrap();
            },
            async {
                follower.flush(&mut ctx_b).await.unwrap();
                follower.flush(&mut ctx_b).await.unwrap();
            }
        );
    }

    #[tokio::test]
    async fn test_compute_pms() {
        let mut rng = ChaCha12Rng::from_seed([0_u8; 32]);
        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let (mut gen, mut ev) = mock_vm();

        let leader_private_key = SecretKey::random(&mut rng);
        let follower_private_key = SecretKey::random(&mut rng);
        let server_private_key = NonZeroScalar::random(&mut rng);
        let server_public_key = PublicKey::from_secret_scalar(&server_private_key);

        let (mut leader, mut follower) = create_pair();

        leader.alloc().unwrap();
        follower.alloc().unwrap();

        leader.private_key = leader_private_key.clone();
        follower.private_key = follower_private_key.clone();

        let leader_pms = leader.setup(&mut gen).unwrap().into_value();
        let leader_pms = gen.decode(leader_pms).unwrap();

        let follower_pms = follower.setup(&mut ev).unwrap().into_value();
        let follower_pms = ev.decode(follower_pms).unwrap();

        tokio::join!(
            async {
                leader.flush(&mut ctx_a).await.unwrap();
                let _client_public_key = leader.client_key().unwrap();
                leader.set_server_key(server_public_key).unwrap();
                leader.flush(&mut ctx_a).await.unwrap();
            },
            async {
                follower.flush(&mut ctx_b).await.unwrap();
                follower.flush(&mut ctx_b).await.unwrap();
            }
        );

        leader.compute_pms(&mut gen).unwrap();
        follower.compute_pms(&mut ev).unwrap();

        tokio::join!(
            async {
                gen.flush(&mut ctx_a).await.unwrap();
                gen.execute(&mut ctx_a).await.unwrap();
                gen.flush(&mut ctx_a)
                    .await
                    .map_err(KeyExchangeError::vm)
                    .unwrap();
            },
            async {
                ev.flush(&mut ctx_b).await.unwrap();
                ev.execute(&mut ctx_b).await.unwrap();
                ev.flush(&mut ctx_b)
                    .await
                    .map_err(KeyExchangeError::vm)
                    .unwrap();
            }
        );

        let (leader_pms, follower_pms) = tokio::try_join!(leader_pms, follower_pms).unwrap();
        assert_eq!(leader_pms, follower_pms);
    }

    #[tokio::test]
    async fn test_compute_ec_shares() {
        let mut rng = ChaCha12Rng::from_seed([0_u8; 32]);
        let (mut ctx_leader, mut ctx_follower) = test_st_executor(8);
        let (leader_converter_0, follower_converter_0) = ideal_share_convert(Block::ZERO);
        let (follower_converter_1, leader_converter_1) = ideal_share_convert(Block::ZERO);

        let leader_converter_0 = Arc::new(Mutex::new(leader_converter_0));
        let leader_converter_1 = Arc::new(Mutex::new(leader_converter_1));
        let follower_converter_0 = Arc::new(Mutex::new(follower_converter_0));
        let follower_converter_1 = Arc::new(Mutex::new(follower_converter_1));

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
                compute_ec_shares(
                    &mut ctx_leader,
                    Role::Leader,
                    leader_converter_0,
                    leader_converter_1,
                    leader_private_key,
                    server_public_key
                ),
                compute_ec_shares(
                    &mut ctx_follower,
                    Role::Follower,
                    follower_converter_0,
                    follower_converter_1,
                    follower_private_key,
                    server_public_key
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
        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let (mut gen, mut ev) = mock_vm();

        let leader_private_key = SecretKey::random(&mut rng);
        let follower_private_key = SecretKey::random(&mut rng);
        let server_private_key = NonZeroScalar::random(&mut rng);
        let server_public_key = PublicKey::from_secret_scalar(&server_private_key);

        let (mut leader, mut follower) = create_pair();

        leader.alloc().unwrap();
        follower.alloc().unwrap();

        leader.private_key = leader_private_key.clone();
        follower.private_key = follower_private_key.clone();

        leader.setup(&mut gen).unwrap();
        follower.setup(&mut ev).unwrap();

        tokio::join!(
            async {
                leader.flush(&mut ctx_a).await.unwrap();
                let _client_public_key = leader.client_key().unwrap();
                leader.set_server_key(server_public_key).unwrap();
                leader.flush(&mut ctx_a).await.unwrap();
            },
            async {
                follower.flush(&mut ctx_b).await.unwrap();
                follower.flush(&mut ctx_b).await.unwrap();
            }
        );

        // Now manipulate pms
        leader.set_pms_0(P256::one());
        follower.set_pms_0(P256::one());

        leader.compute_pms(&mut gen).unwrap();
        follower.compute_pms(&mut ev).unwrap();

        let (leader_res, follower_res) = tokio::join!(
            async {
                gen.flush(&mut ctx_a).await.unwrap();
                gen.execute(&mut ctx_a).await.unwrap();
                gen.flush(&mut ctx_a)
                    .await
                    .map_err(KeyExchangeError::vm)
                    .unwrap();
                leader.flush(&mut ctx_a).await
            },
            async {
                ev.flush(&mut ctx_b).await.unwrap();
                ev.execute(&mut ctx_b).await.unwrap();
                ev.flush(&mut ctx_b)
                    .await
                    .map_err(KeyExchangeError::vm)
                    .unwrap();
                follower.flush(&mut ctx_b).await
            }
        );

        let leader_err = leader_res.unwrap_err();
        let follower_err = follower_res.unwrap_err();

        assert!(matches!(leader_err.kind(), ErrorRepr::ShareConversion(_)));
        assert!(matches!(follower_err.kind(), ErrorRepr::ShareConversion(_)));
    }

    #[tokio::test]
    async fn test_circuit() {
        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let (gen, ev) = mock_vm();

        let share_a0_bytes = [5_u8; 32];
        let share_a1_bytes = [2_u8; 32];

        let share_b0_bytes = [3_u8; 32];
        let share_b1_bytes = [6_u8; 32];

        let (res_gen, res_ev) = tokio::join!(
            async move {
                let mut vm = gen;
                let share_a0: Array<U8, 32> = vm.alloc().unwrap();
                vm.mark_private(share_a0).unwrap();

                let share_b0: Array<U8, 32> = vm.alloc().unwrap();
                vm.mark_blind(share_b0).unwrap();

                let share_a1: Array<U8, 32> = vm.alloc().unwrap();
                vm.mark_private(share_a1).unwrap();

                let share_b1: Array<U8, 32> = vm.alloc().unwrap();
                vm.mark_blind(share_b1).unwrap();

                let pms_circuit = build_pms_circuit();
                let pms_call = CallBuilder::new(pms_circuit)
                    .arg(share_a0)
                    .arg(share_b0)
                    .arg(share_a1)
                    .arg(share_b1)
                    .build()
                    .unwrap();

                let (_, _, eq): (Array<U8, 32>, Array<U8, 32>, Array<U8, 32>) =
                    vm.call(pms_call).unwrap();

                vm.assign(share_a0, share_a0_bytes).unwrap();
                vm.commit(share_a0).unwrap();

                vm.assign(share_a1, share_a1_bytes).unwrap();
                vm.commit(share_a1).unwrap();

                vm.commit(share_b0).unwrap();
                vm.commit(share_b1).unwrap();

                let check = vm.decode(eq).unwrap();

                vm.flush(&mut ctx_a).await.unwrap();
                vm.execute(&mut ctx_a).await.unwrap();
                vm.flush(&mut ctx_a).await.unwrap();
                check.await
            },
            async {
                let mut vm = ev;
                let share_a0: Array<U8, 32> = vm.alloc().unwrap();
                vm.mark_blind(share_a0).unwrap();

                let share_b0: Array<U8, 32> = vm.alloc().unwrap();
                vm.mark_private(share_b0).unwrap();

                let share_a1: Array<U8, 32> = vm.alloc().unwrap();
                vm.mark_blind(share_a1).unwrap();

                let share_b1: Array<U8, 32> = vm.alloc().unwrap();
                vm.mark_private(share_b1).unwrap();

                let pms_circuit = build_pms_circuit();
                let pms_call = CallBuilder::new(pms_circuit)
                    .arg(share_a0)
                    .arg(share_b0)
                    .arg(share_a1)
                    .arg(share_b1)
                    .build()
                    .unwrap();

                let (_, _, eq): (Array<U8, 32>, Array<U8, 32>, Array<U8, 32>) =
                    vm.call(pms_call).unwrap();

                vm.assign(share_b0, share_b0_bytes).unwrap();
                vm.commit(share_b0).unwrap();

                vm.assign(share_b1, share_b1_bytes).unwrap();
                vm.commit(share_b1).unwrap();

                vm.commit(share_a0).unwrap();
                vm.commit(share_a1).unwrap();

                let check = vm.decode(eq).unwrap();

                vm.flush(&mut ctx_b).await.unwrap();
                vm.execute(&mut ctx_b).await.unwrap();
                vm.flush(&mut ctx_b).await.unwrap();
                check.await
            }
        );

        let res_gen = res_gen.unwrap();
        let res_ev = res_ev.unwrap();

        assert_eq!(res_gen, res_ev);
        assert_eq!(res_gen, [0_u8; 32]);
    }

    #[allow(clippy::type_complexity)]
    fn create_pair() -> (
        MpcKeyExchange<IdealShareConvertSender<P256>, IdealShareConvertReceiver<P256>>,
        MpcKeyExchange<IdealShareConvertReceiver<P256>, IdealShareConvertSender<P256>>,
    ) {
        let (leader_converter_0, follower_converter_0) = ideal_share_convert(Block::ZERO);
        let (follower_converter_1, leader_converter_1) = ideal_share_convert(Block::ZERO);

        let leader = MpcKeyExchange::new(
            KeyExchangeConfig::builder()
                .role(Role::Leader)
                .build()
                .unwrap(),
            leader_converter_0,
            leader_converter_1,
        );

        let follower = MpcKeyExchange::new(
            KeyExchangeConfig::builder()
                .role(Role::Follower)
                .build()
                .unwrap(),
            follower_converter_0,
            follower_converter_1,
        );

        (leader, follower)
    }

    fn mock_vm() -> (Generator<IdealCOTSender>, Evaluator<IdealCOTReceiver>) {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (cot_send, cot_recv) = ideal_cot(delta.into_inner());

        let gen = Generator::new(cot_send, [0u8; 16], delta);
        let ev = Evaluator::new(cot_recv);

        (gen, ev)
    }
}
