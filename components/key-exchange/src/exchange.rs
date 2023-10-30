//! This module implements the key exchange logic

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mpz_garble::{value::ValueRef, Decode, Execute, Load, Memory};

use mpz_share_conversion_core::fields::{p256::P256, Field};
use p256::{EncodedPoint, PublicKey, SecretKey};
use point_addition::PointAddition;
use std::fmt::Debug;

use utils_aio::expect_msg_or_err;

use crate::{
    circuit::build_pms_circuit,
    config::{KeyExchangeConfig, Role},
    KeyExchange, KeyExchangeChannel, KeyExchangeError, KeyExchangeMessage, Pms,
};

enum State {
    Initialized,
    Setup {
        share_a: ValueRef,
        share_b: ValueRef,
        share_c: ValueRef,
        share_d: ValueRef,
        pms_1: ValueRef,
        pms_2: ValueRef,
        eq: ValueRef,
    },
    KeyExchange {
        share_a: ValueRef,
        share_b: ValueRef,
        share_c: ValueRef,
        share_d: ValueRef,
        pms_1: ValueRef,
        pms_2: ValueRef,
        eq: ValueRef,
    },
    Complete,
    Error,
}

/// The instance for performing the key exchange protocol
///
/// Can be either a leader or a follower depending on the `role` field in [KeyExchangeConfig]
pub struct KeyExchangeCore<PS, PR, E> {
    /// A channel for exchanging messages between leader and follower
    channel: KeyExchangeChannel,
    /// The sender instance for performing point addition
    point_addition_sender: PS,
    /// The receiver instance for performing point addition
    point_addition_receiver: PR,
    /// MPC executor
    executor: E,
    /// The private key of the party behind this instance, either follower or leader
    private_key: Option<SecretKey>,
    /// The public key of the server
    server_key: Option<PublicKey>,
    /// The config used for the key exchange protocol
    config: KeyExchangeConfig,
    /// The state of the protocol
    state: State,
}

impl<PS, PR, E> Debug for KeyExchangeCore<PS, PR, E>
where
    PS: PointAddition<Point = EncodedPoint, XCoordinate = P256> + Send + Debug,
    PR: PointAddition<Point = EncodedPoint, XCoordinate = P256> + Send + Debug,
    E: Memory + Execute + Decode + Send,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyExchangeCore")
            .field("channel", &"{{ ... }}")
            .field("point_addition_sender", &"{{ ... }}")
            .field("point_addition_receiver", &"{{ ... }}")
            .field("executor", &"{{ ... }}")
            .field("private_key", &"{{ ... }}")
            .field("server_key", &self.server_key)
            .field("config", &self.config)
            .finish()
    }
}

impl<PS, PR, E> KeyExchangeCore<PS, PR, E>
where
    PS: PointAddition<Point = EncodedPoint, XCoordinate = P256> + Send + Debug,
    PR: PointAddition<Point = EncodedPoint, XCoordinate = P256> + Send + Debug,
    E: Memory + Execute + Decode + Send,
{
    /// Creates a new [KeyExchangeCore]
    ///
    /// * `channel`                 - The channel for sending messages between leader and follower
    /// * `point_addition_sender`   - The point addition sender instance used during key exchange
    /// * `point_addition_receiver` - The point addition receiver instance used during key exchange
    /// * `executor`                - The MPC executor
    /// * `config`                  - The config used for the key exchange protocol
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(
            level = "info",
            skip(channel, executor, point_addition_sender, point_addition_receiver),
            ret
        )
    )]
    pub fn new(
        channel: KeyExchangeChannel,
        point_addition_sender: PS,
        point_addition_receiver: PR,
        executor: E,
        config: KeyExchangeConfig,
    ) -> Self {
        Self {
            channel,
            point_addition_sender,
            point_addition_receiver,
            executor,
            private_key: None,
            server_key: None,
            config,
            state: State::Initialized,
        }
    }

    async fn compute_pms_shares(&mut self) -> Result<(P256, P256), KeyExchangeError> {
        let state = std::mem::replace(&mut self.state, State::Error);

        let State::Setup {
            share_a,
            share_b,
            share_c,
            share_d,
            pms_1,
            pms_2,
            eq,
        } = state
        else {
            todo!()
        };

        let server_key = match self.config.role() {
            Role::Leader => {
                // Send server public key to follower
                if let Some(server_key) = &self.server_key {
                    self.channel
                        .send(KeyExchangeMessage::ServerPublicKey((*server_key).into()))
                        .await?;

                    *server_key
                } else {
                    return Err(KeyExchangeError::NoServerKey);
                }
            }
            Role::Follower => {
                // Receive server's public key from leader
                let message =
                    expect_msg_or_err!(self.channel, KeyExchangeMessage::ServerPublicKey)?;
                let server_key = message.try_into()?;

                self.server_key = Some(server_key);

                server_key
            }
        };

        let private_key = self
            .private_key
            .take()
            .ok_or(KeyExchangeError::NoPrivateKey)?;

        // Compute the leader's/follower's share of the pre-master secret
        //
        // We need to mimic the [diffie-hellman](p256::ecdh::diffie_hellman) function without the
        // [SharedSecret](p256::ecdh::SharedSecret) wrapper, because this makes it harder to get
        // the result as an EC curve point.
        let shared_secret = {
            let public_projective = server_key.to_projective();
            (public_projective * private_key.to_nonzero_scalar().as_ref()).to_affine()
        };

        let encoded_point = EncodedPoint::from(PublicKey::from_affine(shared_secret)?);
        let (sender_share, receiver_share) = futures::try_join!(
            self.point_addition_sender
                .compute_x_coordinate_share(encoded_point),
            self.point_addition_receiver
                .compute_x_coordinate_share(encoded_point)
        )?;

        self.state = State::KeyExchange {
            share_a,
            share_b,
            share_c,
            share_d,
            pms_1,
            pms_2,
            eq,
        };

        match self.config.role() {
            Role::Leader => Ok((sender_share, receiver_share)),
            Role::Follower => Ok((receiver_share, sender_share)),
        }
    }

    async fn compute_pms_for(
        &mut self,
        pms_share1: P256,
        pms_share2: P256,
    ) -> Result<Pms, KeyExchangeError> {
        let state = std::mem::replace(&mut self.state, State::Error);

        let State::KeyExchange {
            share_a,
            share_b,
            share_c,
            share_d,
            pms_1,
            pms_2,
            eq,
        } = state
        else {
            todo!()
        };

        let pms_share1: [u8; 32] = pms_share1
            .to_be_bytes()
            .try_into()
            .expect("pms share is 32 bytes");
        let pms_share2: [u8; 32] = pms_share2
            .to_be_bytes()
            .try_into()
            .expect("pms share is 32 bytes");

        match self.config.role() {
            Role::Leader => {
                self.executor.assign(&share_a, pms_share1)?;
                self.executor.assign(&share_c, pms_share2)?;
            }
            Role::Follower => {
                self.executor.assign(&share_b, pms_share1)?;
                self.executor.assign(&share_d, pms_share2)?;
            }
        }

        self.executor
            .execute(
                build_pms_circuit(),
                &[share_a, share_b, share_c, share_d],
                &[pms_1.clone(), pms_2, eq.clone()],
            )
            .await?;

        #[cfg(feature = "tracing")]
        tracing::event!(tracing::Level::DEBUG, "Successfully executed PMS circuit!");

        let mut outputs = self.executor.decode(&[eq]).await?;

        let eq: [u8; 32] = outputs.remove(0).try_into().expect("eq is 32 bytes");

        // Eq should be all zeros if pms_1 == pms_2
        if eq != [0u8; 32] {
            return Err(KeyExchangeError::CheckFailed);
        }

        self.state = State::Complete;

        // Both parties use pms_1 as the pre-master secret
        Ok(Pms::new(pms_1))
    }
}

#[async_trait]
impl<PS, PR, E> KeyExchange for KeyExchangeCore<PS, PR, E>
where
    PS: PointAddition<Point = EncodedPoint, XCoordinate = P256> + Send + Debug,
    PR: PointAddition<Point = EncodedPoint, XCoordinate = P256> + Send + Debug,
    E: Memory + Load + Execute + Decode + Send,
{
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "info", skip(self), ret)
    )]
    fn server_key(&self) -> Option<PublicKey> {
        self.server_key
    }

    /// Set the server's public key
    #[cfg_attr(feature = "tracing", tracing::instrument(level = "info", skip(self)))]
    fn set_server_key(&mut self, server_key: PublicKey) {
        self.server_key = Some(server_key);
    }

    async fn setup(&mut self) -> Result<Pms, KeyExchangeError> {
        let state = std::mem::replace(&mut self.state, State::Error);

        let State::Initialized = state else {
            return Err(KeyExchangeError::InvalidState(
                "expected to be in Initialized state".to_string(),
            ));
        };

        let (share_a, share_b, share_c, share_d) = match self.config.role() {
            Role::Leader => {
                let share_a = self
                    .executor
                    .new_private_input::<[u8; 32]>("pms/share_a")
                    .unwrap();
                let share_b = self
                    .executor
                    .new_blind_input::<[u8; 32]>("pms/share_b")
                    .unwrap();
                let share_c = self
                    .executor
                    .new_private_input::<[u8; 32]>("pms/share_c")
                    .unwrap();
                let share_d = self
                    .executor
                    .new_blind_input::<[u8; 32]>("pms/share_d")
                    .unwrap();

                (share_a, share_b, share_c, share_d)
            }
            Role::Follower => {
                let share_a = self
                    .executor
                    .new_blind_input::<[u8; 32]>("pms/share_a")
                    .unwrap();
                let share_b = self
                    .executor
                    .new_private_input::<[u8; 32]>("pms/share_b")
                    .unwrap();
                let share_c = self
                    .executor
                    .new_blind_input::<[u8; 32]>("pms/share_c")
                    .unwrap();
                let share_d = self
                    .executor
                    .new_private_input::<[u8; 32]>("pms/share_d")
                    .unwrap();

                (share_a, share_b, share_c, share_d)
            }
        };

        let pms_1 = self.executor.new_output::<[u8; 32]>("pms/1")?;
        let pms_2 = self.executor.new_output::<[u8; 32]>("pms/2")?;
        let eq = self.executor.new_output::<[u8; 32]>("pms/eq")?;

        self.executor
            .load(
                build_pms_circuit(),
                &[
                    share_a.clone(),
                    share_b.clone(),
                    share_c.clone(),
                    share_d.clone(),
                ],
                &[pms_1.clone(), pms_2.clone(), eq.clone()],
            )
            .await?;

        self.state = State::Setup {
            share_a,
            share_b,
            share_c,
            share_d,
            pms_1: pms_1.clone(),
            pms_2,
            eq,
        };

        Ok(Pms::new(pms_1))
    }

    /// Compute the client's public key
    ///
    /// The client's public key in this context is the combined public key (EC point addition) of
    /// the leader's public key and the follower's public key.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "info", skip(self, private_key), ret, err)
    )]
    async fn compute_client_key(
        &mut self,
        private_key: SecretKey,
    ) -> Result<Option<PublicKey>, KeyExchangeError> {
        let public_key = private_key.public_key();
        self.private_key = Some(private_key);

        match self.config.role() {
            Role::Leader => {
                // Receive public key from follower
                let message =
                    expect_msg_or_err!(self.channel, KeyExchangeMessage::FollowerPublicKey)?;
                let follower_public_key: PublicKey = message.try_into()?;

                // Combine public keys
                let client_public_key = PublicKey::from_affine(
                    (public_key.to_projective() + follower_public_key.to_projective()).to_affine(),
                )?;

                Ok(Some(client_public_key))
            }
            Role::Follower => {
                // Send public key to leader
                self.channel
                    .send(KeyExchangeMessage::FollowerPublicKey(public_key.into()))
                    .await?;

                Ok(None)
            }
        }
    }

    /// Computes the PMS
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "info", skip(self), err)
    )]
    async fn compute_pms(&mut self) -> Result<Pms, KeyExchangeError> {
        let (pms_share1, pms_share2) = self.compute_pms_shares().await?;

        self.compute_pms_for(pms_share1, pms_share2).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use mpz_garble::{
        protocol::deap::mock::{
            create_mock_deap_vm, MockFollower, MockFollowerThread, MockLeader, MockLeaderThread,
        },
        Vm,
    };
    use mpz_share_conversion_core::fields::{p256::P256, Field};
    use p256::{NonZeroScalar, PublicKey, SecretKey};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::{
        mock::{create_mock_key_exchange_pair, MockKeyExchange},
        KeyExchangeError,
    };

    async fn create_pair() -> (
        (
            MockKeyExchange<MockLeaderThread>,
            MockKeyExchange<MockFollowerThread>,
        ),
        (MockLeader, MockFollower),
    ) {
        let (mut leader_vm, mut follower_vm) = create_mock_deap_vm("test").await;
        (
            create_mock_key_exchange_pair(
                "test",
                leader_vm.new_thread("ke").await.unwrap(),
                follower_vm.new_thread("ke").await.unwrap(),
            ),
            (leader_vm, follower_vm),
        )
    }

    #[tokio::test]
    async fn test_key_exchange() {
        let mut rng = ChaCha20Rng::from_seed([0_u8; 32]);

        let leader_private_key = SecretKey::random(&mut rng);
        let follower_private_key = SecretKey::random(&mut rng);
        let server_public_key = PublicKey::from_secret_scalar(&NonZeroScalar::random(&mut rng));

        let ((mut leader, mut follower), (_leader_vm, _follower_vm)) = create_pair().await;

        let client_public_key = perform_key_exchange(
            &mut leader,
            &mut follower,
            leader_private_key.clone(),
            follower_private_key.clone(),
            server_public_key,
        )
        .await;

        let expected_client_public_key = PublicKey::from_affine(
            (leader_private_key.public_key().to_projective()
                + follower_private_key.public_key().to_projective())
            .to_affine(),
        )
        .unwrap();

        assert_eq!(client_public_key, expected_client_public_key);
    }

    #[tokio::test]
    async fn test_compute_pms_share() {
        let mut rng = ChaCha20Rng::from_seed([0_u8; 32]);

        let leader_private_key = SecretKey::random(&mut rng);
        let follower_private_key = SecretKey::random(&mut rng);
        let server_private_key = NonZeroScalar::random(&mut rng);
        let server_public_key = PublicKey::from_secret_scalar(&server_private_key);

        let ((mut leader, mut follower), (_leader_vm, _follower_vm)) = create_pair().await;

        let client_public_key = perform_key_exchange(
            &mut leader,
            &mut follower,
            leader_private_key.clone(),
            follower_private_key.clone(),
            server_public_key,
        )
        .await;

        leader.set_server_key(server_public_key);

        let ((l_pms1, l_pms2), (f_pms1, f_pms2)) =
            tokio::try_join!(leader.compute_pms_shares(), follower.compute_pms_shares()).unwrap();

        let expected_ecdh_x =
            p256::ecdh::diffie_hellman(server_private_key, client_public_key.as_affine());

        assert_eq!(
            expected_ecdh_x.raw_secret_bytes().to_vec(),
            (l_pms1 + f_pms1).to_be_bytes()
        );
        assert_eq!(
            expected_ecdh_x.raw_secret_bytes().to_vec(),
            (l_pms2 + f_pms2).to_be_bytes()
        );
        assert_eq!(l_pms1 + f_pms1, l_pms2 + f_pms2);
        assert_ne!(l_pms1, f_pms1);
        assert_ne!(l_pms2, f_pms2);
        assert_ne!(l_pms1, l_pms2);
        assert_ne!(f_pms1, f_pms2);
    }

    #[tokio::test]
    async fn test_compute_pms() {
        let mut rng = ChaCha20Rng::from_seed([0_u8; 32]);

        let leader_private_key = SecretKey::random(&mut rng);
        let follower_private_key = SecretKey::random(&mut rng);
        let server_private_key = NonZeroScalar::random(&mut rng);
        let server_public_key = PublicKey::from_secret_scalar(&server_private_key);

        let ((mut leader, mut follower), (_leader_vm, _follower_vm)) = create_pair().await;

        _ = perform_key_exchange(
            &mut leader,
            &mut follower,
            leader_private_key.clone(),
            follower_private_key.clone(),
            server_public_key,
        )
        .await;

        leader.set_server_key(server_public_key);

        let (_leader_pms, _follower_pms) =
            tokio::try_join!(leader.compute_pms(), follower.compute_pms()).unwrap();

        assert_eq!(leader.server_key.unwrap(), server_public_key);
        assert_eq!(follower.server_key.unwrap(), server_public_key);
    }

    #[tokio::test]
    async fn test_compute_pms_fail() {
        let mut rng = ChaCha20Rng::from_seed([0_u8; 32]);

        let leader_private_key = SecretKey::random(&mut rng);
        let follower_private_key = SecretKey::random(&mut rng);
        let server_private_key = NonZeroScalar::random(&mut rng);
        let server_public_key = PublicKey::from_secret_scalar(&server_private_key);

        let ((mut leader, mut follower), (_leader_vm, _follower_vm)) = create_pair().await;

        _ = perform_key_exchange(
            &mut leader,
            &mut follower,
            leader_private_key.clone(),
            follower_private_key.clone(),
            server_public_key,
        )
        .await;

        leader.set_server_key(server_public_key);

        let ((mut l_pms1, l_pms2), (f_pms1, f_pms2)) =
            tokio::try_join!(leader.compute_pms_shares(), follower.compute_pms_shares()).unwrap();

        l_pms1 = l_pms1 + P256::one();

        let err = tokio::try_join!(
            leader.compute_pms_for(l_pms1, l_pms2),
            follower.compute_pms_for(f_pms1, f_pms2)
        )
        .unwrap_err();

        assert!(matches!(err, KeyExchangeError::CheckFailed));
    }

    async fn perform_key_exchange(
        leader: &mut impl KeyExchange,
        follower: &mut impl KeyExchange,
        leader_private_key: SecretKey,
        follower_private_key: SecretKey,
        server_public_key: PublicKey,
    ) -> PublicKey {
        tokio::try_join!(leader.setup(), follower.setup()).unwrap();

        let (client_public_key, _) = tokio::try_join!(
            leader.compute_client_key(leader_private_key),
            follower.compute_client_key(follower_private_key)
        )
        .unwrap();

        leader.set_server_key(server_public_key);

        client_public_key.unwrap()
    }
}
