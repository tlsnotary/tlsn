use async_trait::async_trait;

use crate::{
    ghash::ghash_core::{
        state::{Finalized, Intermediate},
        GhashCore,
    },
    UniversalHash, UniversalHashError,
};
use share_conversion_aio::{AdditiveToMultiplicative, MultiplicativeToAdditive};

mod config;
#[cfg(feature = "mock")]
pub mod mock;

pub use config::{GhashConfig, GhashConfigBuilder, GhashConfigBuilderError};

enum State {
    Init,
    Ready { core: GhashCore<Finalized> },
    Error,
}

/// This is the common instance used by both sender and receiver
///
/// It is an aio wrapper which mostly uses [GhashCore] for computation
pub struct Ghash<T, U>
where
    T: AdditiveToMultiplicative<FieldElement = u128>,
    U: MultiplicativeToAdditive<FieldElement = u128>,
{
    state: State,
    config: GhashConfig,

    a2m_converter: T,
    m2a_converter: U,
}

impl<T, U> Ghash<T, U>
where
    T: AdditiveToMultiplicative<FieldElement = u128>,
    U: MultiplicativeToAdditive<FieldElement = u128>,
{
    /// Creates a new instance
    ///
    /// * `config`              - The configuration of the instance
    /// * `a2m_converter`       - An instance which allows to convert additive into multiplicative
    ///                           shares
    /// * `m2a_converter`       - An instance which allows to convert multiplicative into additive
    ///                           shares
    pub fn new(config: GhashConfig, a2m_converter: T, m2a_converter: U) -> Self {
        Self {
            state: State::Init,
            config,
            a2m_converter,
            m2a_converter,
        }
    }

    /// Computes all the additive shares of the hashkey powers
    ///
    /// We need this when the max block count changes.
    async fn compute_add_shares(
        &mut self,
        core: GhashCore<Intermediate>,
    ) -> Result<GhashCore<Finalized>, UniversalHashError> {
        let odd_mul_shares = core.odd_mul_shares();

        let add_shares = self.m2a_converter.m_to_a(odd_mul_shares).await?;
        let core = core.add_new_add_shares(&add_shares);

        Ok(core)
    }
}

#[async_trait]
impl<T, U> UniversalHash for Ghash<T, U>
where
    T: AdditiveToMultiplicative<FieldElement = u128> + Send,
    U: MultiplicativeToAdditive<FieldElement = u128> + Send,
{
    const KEY_SIZE: usize = 16;
    const BLOCK_SIZE: usize = 16;

    async fn set_key(&mut self, key: Vec<u8>) -> Result<(), UniversalHashError> {
        if key.len() != 16 {
            return Err(UniversalHashError::KeyLengthError(16, key.len()));
        }

        if !matches!(&self.state, State::Init) {
            return Err(UniversalHashError::InvalidState(
                "Key already set".to_string(),
            ));
        }

        let mut h_additive = [0u8; 16];
        h_additive.copy_from_slice(key.as_slice());

        let h_additive = u128::from_be_bytes(h_additive);
        let h_multiplicative = self.a2m_converter.a_to_m(vec![h_additive]).await?;

        let core = GhashCore::new(self.config.initial_block_count);
        let core = core.compute_odd_mul_powers(h_multiplicative[0]);
        let core = self.compute_add_shares(core).await?;

        self.state = State::Ready { core };

        Ok(())
    }

    async fn finalize(&mut self, mut input: Vec<u8>) -> Result<Vec<u8>, UniversalHashError> {
        // Divide by block length and round up
        let block_count = input.len() / 16 + (input.len() % 16 != 0) as usize;

        if block_count > self.config.max_block_count {
            return Err(UniversalHashError::InputLengthError(input.len()));
        }

        let state = std::mem::replace(&mut self.state, State::Error);

        // Calling finalize when not setup is a fatal error
        let State::Ready { core } = state else {
            return Err(UniversalHashError::InvalidState(
                "Key not set".to_string(),
            ));
        };

        // Compute new shares if the block count increased
        let core = if block_count > core.get_max_blocks() {
            self.compute_add_shares(core.change_max_hashkey(block_count))
                .await?
        } else {
            core
        };

        // Pad input to a multiple of 16 bytes
        input.resize(block_count * 16, 0);

        // Convert input to blocks
        let blocks = input
            .chunks_exact(16)
            .map(|chunk| {
                let mut block = [0u8; 16];
                block.copy_from_slice(chunk);
                u128::from_be_bytes(block)
            })
            .collect::<Vec<u128>>();

        let tag = core
            .finalize(&blocks)
            .expect("Input length should be valid");

        // Reinsert state
        self.state = State::Ready { core };

        Ok(tag.to_be_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::{mock::mock_ghash_pair, UniversalHash};
    use ghash_rc::{
        universal_hash::{NewUniversalHash, UniversalHash as UniversalHashReference},
        GHash as GhashReference,
    };
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;
    use share_conversion_aio::gf2_128::recorder::Void;

    #[tokio::test]
    async fn test_ghash_output() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let h: u128 = rng.gen();
        let sender_key: u128 = rng.gen();
        let receiver_key: u128 = h ^ sender_key;
        let message: Vec<u8> = (0..128).map(|_| rng.gen()).collect();

        let (mut sender, mut receiver) = mock_ghash_pair::<Void, Void>(message.len());

        let (sender_setup_fut, receiver_setup_fut) = (
            sender.set_key(sender_key.to_be_bytes().to_vec()),
            receiver.set_key(receiver_key.to_be_bytes().to_vec()),
        );

        let (sender_result, receiver_result) = tokio::join!(sender_setup_fut, receiver_setup_fut);
        sender_result.unwrap();
        receiver_result.unwrap();

        let sender_share_fut = sender.finalize(message.clone());
        let receiver_share_fut = receiver.finalize(message.clone());

        let (sender_share, receiver_share) = tokio::join!(sender_share_fut, receiver_share_fut);
        let sender_share = sender_share.unwrap();
        let receiver_share = receiver_share.unwrap();

        let tag = sender_share
            .iter()
            .zip(receiver_share.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        assert_eq!(tag, ghash_reference_impl(h, &message));
    }

    #[tokio::test]
    async fn test_ghash_output_padded() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let h: u128 = rng.gen();
        let sender_key: u128 = rng.gen();
        let receiver_key: u128 = h ^ sender_key;

        // Message length is not a multiple of the block length
        let message: Vec<u8> = (0..126).map(|_| rng.gen()).collect();

        let (mut sender, mut receiver) = mock_ghash_pair::<Void, Void>(message.len());

        let (sender_setup_fut, receiver_setup_fut) = (
            sender.set_key(sender_key.to_be_bytes().to_vec()),
            receiver.set_key(receiver_key.to_be_bytes().to_vec()),
        );

        let (sender_result, receiver_result) = tokio::join!(sender_setup_fut, receiver_setup_fut);
        sender_result.unwrap();
        receiver_result.unwrap();

        let sender_share_fut = sender.finalize(message.clone());
        let receiver_share_fut = receiver.finalize(message.clone());

        let (sender_share, receiver_share) = tokio::join!(sender_share_fut, receiver_share_fut);
        let sender_share = sender_share.unwrap();
        let receiver_share = receiver_share.unwrap();

        let tag = sender_share
            .iter()
            .zip(receiver_share.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        assert_eq!(tag, ghash_reference_impl(h, &message));
    }

    #[tokio::test]
    async fn test_ghash_long_message() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let h: u128 = rng.gen();
        let sender_key: u128 = rng.gen();
        let receiver_key: u128 = h ^ sender_key;
        let short_message: Vec<u8> = (0..128).map(|_| rng.gen()).collect();

        // A longer message
        let long_message: Vec<u8> = (0..192).map(|_| rng.gen()).collect();

        // Create and setup sender and receiver for short message length
        let (mut sender, mut receiver) = mock_ghash_pair::<Void, Void>(short_message.len());

        let (sender_setup_fut, receiver_setup_fut) = (
            sender.set_key(sender_key.to_be_bytes().to_vec()),
            receiver.set_key(receiver_key.to_be_bytes().to_vec()),
        );

        let (sender_result, receiver_result) = tokio::join!(sender_setup_fut, receiver_setup_fut);
        sender_result.unwrap();
        receiver_result.unwrap();

        // Compute the shares for the short message
        let sender_share_fut = sender.finalize(short_message.clone());
        let receiver_share_fut = receiver.finalize(short_message.clone());

        let (sender_result, receiver_result) = tokio::join!(sender_share_fut, receiver_share_fut);
        let (_, _) = (sender_result.unwrap(), receiver_result.unwrap());

        // Now compute the shares for the longer message
        let sender_share_fut = sender.finalize(long_message.clone());
        let receiver_share_fut = receiver.finalize(long_message.clone());

        let (sender_result, receiver_result) = tokio::join!(sender_share_fut, receiver_share_fut);
        let (sender_share, receiver_share) = (sender_result.unwrap(), receiver_result.unwrap());

        let tag = sender_share
            .iter()
            .zip(receiver_share.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        assert_eq!(tag, ghash_reference_impl(h, &long_message));

        // We should still be able to generate a Ghash output for the shorter message
        let sender_share_fut = sender.finalize(short_message.clone());
        let receiver_share_fut = receiver.finalize(short_message.clone());

        let (sender_result, receiver_result) = tokio::join!(sender_share_fut, receiver_share_fut);
        let (sender_share, receiver_share) = (sender_result.unwrap(), receiver_result.unwrap());

        let tag = sender_share
            .iter()
            .zip(receiver_share.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        assert_eq!(tag, ghash_reference_impl(h, &short_message));
    }

    fn ghash_reference_impl(h: u128, message: &[u8]) -> Vec<u8> {
        let mut ghash = GhashReference::new(&h.to_be_bytes().into());
        ghash.update_padded(&message);
        let mac = ghash.finalize();
        mac.into_bytes().to_vec()
    }
}
