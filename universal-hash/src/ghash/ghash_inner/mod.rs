use crate::{
    ghash::ghash_core::{
        state::{Finalized, Intermediate},
        GhashCore,
    },
    UniversalHash, UniversalHashError,
};
use async_trait::async_trait;
use mpc_core::Block;
use mpc_share_conversion::{Gf2_128, ShareConversion};

mod config;
#[cfg(feature = "mock")]
pub(crate) mod mock;

pub use config::{GhashConfig, GhashConfigBuilder, GhashConfigBuilderError};

#[derive(Debug)]
enum State {
    Init,
    Ready { core: GhashCore<Finalized> },
    Error,
}

/// This is the common instance used by both sender and receiver
///
/// It is an aio wrapper which mostly uses [GhashCore] for computation
#[derive(Debug)]
pub struct Ghash<C> {
    state: State,
    config: GhashConfig,
    converter: C,
}

impl<C> Ghash<C>
where
    C: ShareConversion<Gf2_128> + Send + Sync,
{
    /// Creates a new instance
    ///
    /// * `config`      - The configuration for this Ghash instance
    /// * `converter`   - An instance which allows to convert multiplicative into additive shares
    ///                   and vice versa
    #[cfg_attr(feature = "tracing", tracing::instrument(level = "info"), ret)]
    pub fn new(config: GhashConfig, converter: C) -> Self {
        Self {
            state: State::Init,
            config,
            converter,
        }
    }

    /// Computes all the additive shares of the hashkey powers
    ///
    /// We need this when the max block count changes.
    #[cfg_attr(feature = "tracing", tracing::instrument(level = "debug"), err)]
    async fn compute_add_shares(
        &mut self,
        core: GhashCore<Intermediate>,
    ) -> Result<GhashCore<Finalized>, UniversalHashError> {
        let odd_mul_shares = core.odd_mul_shares();

        let add_shares = self.converter.to_additive(odd_mul_shares).await?;
        let core = core.add_new_add_shares(&add_shares);

        Ok(core)
    }
}

#[async_trait]
impl<C> UniversalHash for Ghash<C>
where
    C: ShareConversion<Gf2_128> + Send + Sync,
{
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "info", skip(key), err)
    )]
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

        // GHASH reflects the bits of the key
        let h_additive = Gf2_128::new(u128::from_be_bytes(h_additive).reverse_bits());

        let h_multiplicative = self.converter.to_multiplicative(vec![h_additive]).await?;

        let core = GhashCore::new(self.config.initial_block_count);
        let core = core.compute_odd_mul_powers(h_multiplicative[0]);
        let core = self.compute_add_shares(core).await?;

        self.state = State::Ready { core };

        Ok(())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(level = "info"), ret, err)]
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
                Block::from(block)
            })
            .collect::<Vec<Block>>();

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
    use super::{mock::mock_ghash_pair, GhashConfig, UniversalHash};
    use ghash_rc::{
        universal_hash::{KeyInit, UniversalHash as UniversalHashReference},
        GHash as GhashReference,
    };
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    fn create_pair(id: &str, block_count: usize) -> (impl UniversalHash, impl UniversalHash) {
        let config = GhashConfig::builder()
            .id(id)
            .initial_block_count(block_count)
            .build()
            .unwrap();

        mock_ghash_pair(config.clone(), config)
    }

    #[tokio::test]
    async fn test_ghash_output() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let h: u128 = rng.gen();
        let sender_key: u128 = rng.gen();
        let receiver_key: u128 = h ^ sender_key;
        let message: Vec<u8> = (0..128).map(|_| rng.gen()).collect();

        let (mut sender, mut receiver) = create_pair("test", 1);

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

        let (mut sender, mut receiver) = create_pair("test", 1);

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
        let (mut sender, mut receiver) = create_pair("test", 1);

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
        ghash.update_padded(message);
        let mac = ghash.finalize();
        mac.to_vec()
    }
}
