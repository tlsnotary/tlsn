use crate::{
    ghash::ghash_core::{
        state::{Finalized, Intermediate},
        GhashCore,
    },
    UniversalHash, UniversalHashError,
};
use async_trait::async_trait;
use mpz_common::{Context, Preprocess};
use mpz_core::Block;
use mpz_fields::gf2_128::Gf2_128;
use mpz_share_conversion::{ShareConversionError, ShareConvert};
use std::fmt::Debug;
use tracing::instrument;

mod config;
#[cfg(feature = "ideal")]
pub(crate) mod ideal;

pub use config::{GhashConfig, GhashConfigBuilder, GhashConfigBuilderError};

#[derive(Debug)]
enum State {
    Init,
    Ready { core: GhashCore<Finalized> },
    Error,
}

/// This is the common instance used by both sender and receiver.
///
/// It is an aio wrapper which mostly uses [GhashCore] for computation.
pub struct Ghash<C, Ctx> {
    state: State,
    config: GhashConfig,
    converter: C,
    context: Ctx,
}

impl<C, Ctx> Ghash<C, Ctx>
where
    Ctx: Context,
    C: ShareConvert<Ctx, Gf2_128>,
{
    /// Creates a new instance.
    ///
    /// # Arguments
    ///
    /// * `config`      - The configuration for this Ghash instance.
    /// * `converter`   - An instance which allows to convert multiplicative into additive shares
    ///                   and vice versa.
    /// * `context`     - The context.
    pub fn new(config: GhashConfig, converter: C, context: Ctx) -> Self {
        Self {
            state: State::Init,
            config,
            converter,
            context,
        }
    }

    /// Computes all the additive shares of the hashkey powers.
    ///
    /// We need this when the max block count changes.
    #[instrument(level = "debug", skip_all, err)]
    async fn compute_add_shares(
        &mut self,
        core: GhashCore<Intermediate>,
    ) -> Result<GhashCore<Finalized>, UniversalHashError> {
        let odd_mul_shares = core.odd_mul_shares();

        let add_shares = self
            .converter
            .to_additive(&mut self.context, odd_mul_shares)
            .await?;
        let core = core.add_new_add_shares(&add_shares);

        Ok(core)
    }
}

impl<C, Ctx> Debug for Ghash<C, Ctx> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ghash")
            .field("state", &self.state)
            .field("config", &self.config)
            .field("converter", &"{{ .. }}".to_string())
            .finish()
    }
}

#[async_trait]
impl<Ctx, C> UniversalHash for Ghash<C, Ctx>
where
    Ctx: Context,
    C: Preprocess<Ctx, Error = ShareConversionError> + ShareConvert<Ctx, Gf2_128> + Send,
{
    #[instrument(level = "info", fields(thread = %self.context.id()), skip_all, err)]
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

        // GHASH reflects the bits of the key.
        let h_additive = Gf2_128::new(u128::from_be_bytes(h_additive).reverse_bits());

        let h_multiplicative = self
            .converter
            .to_multiplicative(&mut self.context, vec![h_additive])
            .await?;

        let core = GhashCore::new(self.config.initial_block_count);
        let core = core.compute_odd_mul_powers(h_multiplicative[0]);
        let core = self.compute_add_shares(core).await?;

        self.state = State::Ready { core };

        Ok(())
    }

    #[instrument(level = "debug", fields(thread = %self.context.id()), skip_all, err)]
    async fn setup(&mut self) -> Result<(), UniversalHashError> {
        // We need only half the number of `max_block_count` M2As because of the free squaring trick
        // and we need one extra A2M conversion in the beginning. Both M2A and A2M, each require a single
        // OLE.
        let ole_count = self.config.max_block_count / 2 + 1;
        self.converter.alloc(ole_count);

        Ok(())
    }

    #[instrument(level = "debug", fields(thread = %self.context.id()), skip_all, err)]
    async fn preprocess(&mut self) -> Result<(), UniversalHashError> {
        self.converter.preprocess(&mut self.context).await?;

        Ok(())
    }

    #[instrument(level = "debug", fields(thread = %self.context.id()), skip_all, err)]
    async fn finalize(&mut self, mut input: Vec<u8>) -> Result<Vec<u8>, UniversalHashError> {
        // Divide by block length and round up.
        let block_count = input.len() / 16 + (input.len() % 16 != 0) as usize;

        if block_count > self.config.max_block_count {
            return Err(UniversalHashError::InputLengthError(input.len()));
        }

        let state = std::mem::replace(&mut self.state, State::Error);

        // Calling finalize when not setup is a fatal error.
        let State::Ready { core } = state else {
            return Err(UniversalHashError::InvalidState("Key not set".to_string()));
        };

        // Compute new shares if the block count increased.
        let core = if block_count > core.get_max_blocks() {
            self.compute_add_shares(core.change_max_hashkey(block_count))
                .await?
        } else {
            core
        };

        // Pad input to a multiple of 16 bytes.
        input.resize(block_count * 16, 0);

        // Convert input to blocks.
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

        // Reinsert state.
        self.state = State::Ready { core };

        Ok(tag.to_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        ghash::{Ghash, GhashConfig},
        UniversalHash,
    };
    use ghash_rc::{
        universal_hash::{KeyInit, UniversalHash as UniversalHashReference},
        GHash as GhashReference,
    };
    use mpz_common::{executor::test_st_executor, Context};
    use mpz_share_conversion::ideal::{ideal_share_converter, IdealShareConverter};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    fn create_pair<Ctx: Context>(
        block_count: usize,
        context_alice: Ctx,
        context_bob: Ctx,
    ) -> (
        Ghash<IdealShareConverter, Ctx>,
        Ghash<IdealShareConverter, Ctx>,
    ) {
        let (convert_a, convert_b) = ideal_share_converter();

        let config = GhashConfig::builder()
            .initial_block_count(block_count)
            .build()
            .unwrap();

        (
            Ghash::new(config.clone(), convert_a, context_alice),
            Ghash::new(config, convert_b, context_bob),
        )
    }

    #[tokio::test]
    async fn test_ghash_output() {
        let (ctx_a, ctx_b) = test_st_executor(8);
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let h: u128 = rng.gen();
        let sender_key: u128 = rng.gen();
        let receiver_key: u128 = h ^ sender_key;
        let message: Vec<u8> = (0..128).map(|_| rng.gen()).collect();

        let (mut sender, mut receiver) = create_pair(1, ctx_a, ctx_b);

        tokio::try_join!(
            sender.set_key(sender_key.to_be_bytes().to_vec()),
            receiver.set_key(receiver_key.to_be_bytes().to_vec())
        )
        .unwrap();

        let (sender_share, receiver_share) = tokio::try_join!(
            sender.finalize(message.clone()),
            receiver.finalize(message.clone())
        )
        .unwrap();

        let tag = sender_share
            .iter()
            .zip(receiver_share.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        assert_eq!(tag, ghash_reference_impl(h, &message));
    }

    #[tokio::test]
    async fn test_ghash_output_padded() {
        let (ctx_a, ctx_b) = test_st_executor(8);
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let h: u128 = rng.gen();
        let sender_key: u128 = rng.gen();
        let receiver_key: u128 = h ^ sender_key;

        // Message length is not a multiple of the block length
        let message: Vec<u8> = (0..126).map(|_| rng.gen()).collect();

        let (mut sender, mut receiver) = create_pair(1, ctx_a, ctx_b);

        tokio::try_join!(
            sender.set_key(sender_key.to_be_bytes().to_vec()),
            receiver.set_key(receiver_key.to_be_bytes().to_vec())
        )
        .unwrap();

        let (sender_share, receiver_share) = tokio::try_join!(
            sender.finalize(message.clone()),
            receiver.finalize(message.clone())
        )
        .unwrap();

        let tag = sender_share
            .iter()
            .zip(receiver_share.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        assert_eq!(tag, ghash_reference_impl(h, &message));
    }

    #[tokio::test]
    async fn test_ghash_long_message() {
        let (ctx_a, ctx_b) = test_st_executor(8);
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let h: u128 = rng.gen();
        let sender_key: u128 = rng.gen();
        let receiver_key: u128 = h ^ sender_key;
        let short_message: Vec<u8> = (0..128).map(|_| rng.gen()).collect();

        // A longer message.
        let long_message: Vec<u8> = (0..192).map(|_| rng.gen()).collect();

        // Create and setup sender and receiver for short message length.
        let (mut sender, mut receiver) = create_pair(1, ctx_a, ctx_b);

        tokio::try_join!(
            sender.set_key(sender_key.to_be_bytes().to_vec()),
            receiver.set_key(receiver_key.to_be_bytes().to_vec())
        )
        .unwrap();

        // Compute the shares for the short message.
        tokio::try_join!(
            sender.finalize(short_message.clone()),
            receiver.finalize(short_message.clone())
        )
        .unwrap();

        // Now compute the shares for the longer message.
        let (sender_share, receiver_share) = tokio::try_join!(
            sender.finalize(long_message.clone()),
            receiver.finalize(long_message.clone())
        )
        .unwrap();

        let tag = sender_share
            .iter()
            .zip(receiver_share.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        assert_eq!(tag, ghash_reference_impl(h, &long_message));

        // We should still be able to generate a Ghash output for the shorter message.
        let (sender_share, receiver_share) = tokio::try_join!(
            sender.finalize(short_message.clone()),
            receiver.finalize(short_message.clone())
        )
        .unwrap();

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
