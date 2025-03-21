mod compute;
mod verify;

pub(crate) use compute::{ComputeTagData, ComputeTags};
pub(crate) use verify::{VerifyTagData, VerifyTags};

use std::{fmt::Debug, ops::Add};

use async_trait::async_trait;
use mpz_common::{future::Output, Context, Flush};
use mpz_core::Block;
use mpz_fields::{gf2_128::Gf2_128, Field};
use mpz_share_conversion::{AdditiveToMultiplicative, MultiplicativeToAdditive};
use serde::{Deserialize, Serialize};

use crate::record_layer::aead::AeadError;

/// Maximum exponent used in GHASH.
const MAX_POWER: usize = 1026;

#[async_trait]
pub(crate) trait Ghash {
    /// Allocates resources needed for GHASH.
    fn alloc(&mut self) -> Result<(), GhashError>;

    /// Preprocesses GHASH.
    async fn preprocess(&mut self, ctx: &mut Context) -> Result<(), GhashError>;

    /// Sets the additive key share for the hash function.
    fn set_key(&mut self, key: Vec<u8>) -> Result<(), GhashError>;

    /// Sets up GHASH, computing the key shares.
    async fn setup(&mut self, ctx: &mut Context) -> Result<(), GhashError>;

    /// Computes the GHASH tag share.
    fn compute(&self, input: &[u8]) -> Result<Vec<u8>, GhashError>;
}

/// MPC GHASH implementation.
pub(crate) struct MpcGhash<C> {
    state: State,
    converter: C,
    alloc: bool,
}

#[derive(Debug)]
enum State {
    Init,
    SetKey { key: Gf2_128 },
    Ready { shares: Vec<Gf2_128> },
    Error,
}

impl State {
    fn take(&mut self) -> Self {
        std::mem::replace(self, State::Error)
    }
}

impl<C> MpcGhash<C> {
    /// Creates a new instance.
    ///
    /// # Arguments
    ///
    /// * `converter` - GF2_128 share converter.
    pub(crate) fn new(converter: C) -> Self {
        Self {
            state: State::Init,
            converter,
            alloc: false,
        }
    }
}

#[async_trait]
impl<C> Ghash for MpcGhash<C>
where
    C: AdditiveToMultiplicative<Gf2_128> + Flush + Send,
    C: MultiplicativeToAdditive<Gf2_128> + Flush + Send,
{
    fn alloc(&mut self) -> Result<(), GhashError> {
        if !self.alloc {
            // Odd powers are computed using M2A, even powers are computed
            // locally. We need one extra A2M conversion in the beginning.
            // Both M2A and A2M, each require a single OLE.
            AdditiveToMultiplicative::<Gf2_128>::alloc(&mut self.converter, 1)
                .map_err(GhashError::conversion)?;

            // -1 because the odd power H^1 is already known at this point.
            MultiplicativeToAdditive::<Gf2_128>::alloc(&mut self.converter, (MAX_POWER / 2) - 1)
                .map_err(GhashError::conversion)?;

            self.alloc = true;
        }

        Ok(())
    }

    async fn preprocess(&mut self, ctx: &mut Context) -> Result<(), GhashError> {
        self.converter
            .flush(ctx)
            .await
            .map_err(GhashError::conversion)
    }

    fn set_key(&mut self, key: Vec<u8>) -> Result<(), GhashError> {
        if key.len() != 16 {
            return Err(ErrorRepr::KeyLength {
                expected: 16,
                actual: key.len(),
            }
            .into());
        }

        let State::Init = self.state.take() else {
            return Err(GhashError::state("Key already set"));
        };

        let mut h_additive = [0u8; 16];
        h_additive.copy_from_slice(key.as_slice());

        // GHASH reflects the bits of the key.
        let h_additive = Gf2_128::new(u128::from_be_bytes(h_additive).reverse_bits());

        self.state = State::SetKey { key: h_additive };

        Ok(())
    }

    async fn setup(&mut self, ctx: &mut Context) -> Result<(), GhashError> {
        let State::SetKey { key: add_key } = self.state.take() else {
            return Err(GhashError::state("cannot setup before key is set"));
        };

        let mut mult_key = self
            .converter
            .queue_to_multiplicative(&[add_key])
            .map_err(GhashError::conversion)?;

        self.converter
            .flush(ctx)
            .await
            .map_err(GhashError::conversion)?;

        let mult_key = mult_key
            .try_recv()
            .map_err(GhashError::conversion)?
            .expect("share should be computed")
            .shares[0];

        // Compute the odd powers of the multiplicative key share.
        //
        // Resulting vector contains odd powers of H from H^3 to H^1025.
        let odd_shares: Vec<_> = (0..MAX_POWER)
            .scan(mult_key, |acc, _| {
                let power_n = *acc;
                *acc = power_n * mult_key;
                Some(power_n)
            })
            // Start from H^3.
            .skip(2)
            // Skip even powers.
            .step_by(2)
            .collect();

        // Compute the additive shares of the odd powers.
        let mut add_shares_odd = self
            .converter
            .queue_to_additive(&odd_shares)
            .map_err(GhashError::conversion)?;

        self.converter
            .flush(ctx)
            .await
            .map_err(GhashError::conversion)?;

        let add_shares_odd = add_shares_odd
            .try_recv()
            .map_err(GhashError::conversion)?
            .expect("share should be computed")
            .shares;

        let shares = compute_shares(add_key, &add_shares_odd);

        self.state = State::Ready { shares };

        Ok(())
    }

    fn compute(&self, input: &[u8]) -> Result<Vec<u8>, GhashError> {
        let State::Ready { shares } = &self.state else {
            return Err(GhashError::state("key shares are not computed"));
        };

        // Divide by block length and round up.
        let block_count = input.len() / 16 + (input.len() % 16 != 0) as usize;

        if block_count > MAX_POWER {
            return Err(ErrorRepr::InputLength {
                len: block_count,
                max: MAX_POWER * 16,
            }
            .into());
        }

        let mut input = input.to_vec();

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

        let offset = shares.len() - blocks.len();
        let tag: Block = blocks
            .iter()
            .zip(shares.iter().rev().skip(offset))
            .fold(Gf2_128::zero(), |acc, (block, share)| {
                acc + Gf2_128::from(block.reverse_bits()) * *share
            })
            .into();

        Ok(tag.reverse_bits().to_bytes().to_vec())
    }
}

/// Computes shares of powers of H.
///
/// # Arguments
///
/// * `key` - Additive share of H.
/// * `odd_powers` - Additive shares of odd powers of H starting at H^3.
fn compute_shares(key: Gf2_128, odd_powers: &[Gf2_128]) -> Vec<Gf2_128> {
    let mut shares = Vec::with_capacity(MAX_POWER);

    // H^1
    shares.push(key);

    let mut odd_idx = 0;
    for i in 2..=MAX_POWER {
        if i % 2 == 0 {
            // Even power, compute by squaring the square root power.
            let base = shares[i / 2 - 1];
            shares.push(base * base);
        } else {
            // Odd power.
            shares.push(odd_powers[odd_idx]);
            odd_idx += 1;
        }
    }

    shares
}

/// Builds padded data for GHASH.
pub(crate) fn build_ghash_data(mut aad: Vec<u8>, mut ciphertext: Vec<u8>) -> Vec<u8> {
    let associated_data_bitlen = (aad.len() as u64) * 8;
    let text_bitlen = (ciphertext.len() as u64) * 8;

    let len_block = ((associated_data_bitlen as u128) << 64) + (text_bitlen as u128);

    // Pad data to be a multiple of 16 bytes.
    let aad_padded_block_count = (aad.len() / 16) + (aad.len() % 16 != 0) as usize;
    aad.resize(aad_padded_block_count * 16, 0);

    let ciphertext_padded_block_count =
        (ciphertext.len() / 16) + (ciphertext.len() % 16 != 0) as usize;
    ciphertext.resize(ciphertext_padded_block_count * 16, 0);

    let mut data: Vec<u8> = Vec::with_capacity(aad.len() + ciphertext.len() + 16);
    data.extend(aad);
    data.extend(ciphertext);
    data.extend_from_slice(&len_block.to_be_bytes());

    data
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TagShare([u8; 16]);

impl Add for TagShare {
    type Output = Vec<u8>;

    fn add(mut self, rhs: Self) -> Self::Output {
        self.0.iter_mut().zip(rhs.0).for_each(|(a, b)| *a ^= b);
        self.0.to_vec()
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct GhashError(#[from] ErrorRepr);

impl GhashError {
    fn conversion<E>(error: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::ShareConversion(error.into()))
    }

    fn state(reason: impl ToString) -> Self {
        Self(ErrorRepr::State(reason.to_string()))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("ghash error: {0}")]
enum ErrorRepr {
    #[error("share conversion error: {0}")]
    ShareConversion(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("invalid state: {0}")]
    State(String),
    #[error("incorrect key length, expected: {expected}, actual: {actual}")]
    KeyLength { expected: usize, actual: usize },
    #[error("input length exceeds maximum: {len} > {max}")]
    InputLength { len: usize, max: usize },
}

impl From<GhashError> for AeadError {
    fn from(value: GhashError) -> Self {
        AeadError::tag(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghash_rc::{
        universal_hash::{KeyInit, UniversalHash as UniversalHashReference},
        GHash as GhashReference,
    };
    use mpz_common::context::test_st_context;
    use mpz_core::Block;
    use mpz_fields::{gf2_128::Gf2_128, UniformRand};
    use mpz_share_conversion::ideal::{
        ideal_share_convert, IdealShareConvertReceiver, IdealShareConvertSender,
    };
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use rand06_compat::Rand0_6CompatExt;
    fn create_pair() -> (
        MpcGhash<IdealShareConvertSender<Gf2_128>>,
        MpcGhash<IdealShareConvertReceiver<Gf2_128>>,
    ) {
        let (convert_a, convert_b) = ideal_share_convert(Block::ZERO);

        let (mut sender, mut receiver) = (MpcGhash::new(convert_a), MpcGhash::new(convert_b));
        sender.alloc().unwrap();
        receiver.alloc().unwrap();

        (sender, receiver)
    }

    #[test]
    fn test_compute_shares() {
        let mut rng = StdRng::seed_from_u64(0).compat();

        let key = Gf2_128::rand(&mut rng);
        let expected_powers: Vec<_> = (0..MAX_POWER)
            .scan(key, |acc, _| {
                let power_n = *acc;
                *acc = power_n * key;
                Some(power_n)
            })
            .collect();

        let odd_powers = expected_powers
            .iter()
            .skip(2)
            .step_by(2)
            .cloned()
            .collect::<Vec<_>>();

        let powers = compute_shares(key, &odd_powers);

        assert_eq!(powers, expected_powers);
    }

    #[tokio::test]
    async fn test_ghash_output() {
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let mut rng = StdRng::seed_from_u64(0);
        let h: u128 = rng.random();
        let sender_key: u128 = rng.random();
        let receiver_key: u128 = h ^ sender_key;

        let message: Vec<u8> = (0..16).map(|_| rng.random()).collect();

        let (mut sender, mut receiver) = create_pair();
        sender.set_key(sender_key.to_be_bytes().to_vec()).unwrap();
        receiver
            .set_key(receiver_key.to_be_bytes().to_vec())
            .unwrap();

        tokio::try_join!(sender.setup(&mut ctx_a), receiver.setup(&mut ctx_b)).unwrap();

        let sender_share = sender.compute(&message).unwrap();
        let receiver_share = receiver.compute(&message).unwrap();

        let tag = sender_share
            .iter()
            .zip(receiver_share.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        assert_eq!(tag, ghash_reference_impl(h, &message));
    }

    #[tokio::test]
    async fn test_ghash_output_padded() {
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let mut rng = StdRng::seed_from_u64(0);
        let h: u128 = rng.random();
        let sender_key: u128 = rng.random();
        let receiver_key: u128 = h ^ sender_key;

        // Message length is not a multiple of the block length.
        let message: Vec<u8> = (0..14).map(|_| rng.random()).collect();

        let (mut sender, mut receiver) = create_pair();

        sender.set_key(sender_key.to_be_bytes().to_vec()).unwrap();
        receiver
            .set_key(receiver_key.to_be_bytes().to_vec())
            .unwrap();

        tokio::try_join!(sender.setup(&mut ctx_a), receiver.setup(&mut ctx_b)).unwrap();

        let sender_share = sender.compute(&message).unwrap();
        let receiver_share = receiver.compute(&message).unwrap();

        let tag = sender_share
            .iter()
            .zip(receiver_share.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        assert_eq!(tag, ghash_reference_impl(h, &message));
    }

    #[tokio::test]
    async fn test_ghash_long_message() {
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let mut rng = StdRng::seed_from_u64(0);
        let h: u128 = rng.random();
        let sender_key: u128 = rng.random();
        let receiver_key: u128 = h ^ sender_key;

        // A longer message.
        let long_message: Vec<u8> = (0..30).map(|_| rng.random()).collect();

        let (mut sender, mut receiver) = create_pair();

        sender.set_key(sender_key.to_be_bytes().to_vec()).unwrap();
        receiver
            .set_key(receiver_key.to_be_bytes().to_vec())
            .unwrap();

        tokio::try_join!(sender.setup(&mut ctx_a), receiver.setup(&mut ctx_b)).unwrap();

        let sender_share = sender.compute(&long_message).unwrap();
        let receiver_share = receiver.compute(&long_message).unwrap();

        let tag = sender_share
            .iter()
            .zip(receiver_share.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        assert_eq!(tag, ghash_reference_impl(h, &long_message));
    }

    #[tokio::test]
    async fn test_ghash_repeated() {
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let mut rng = StdRng::seed_from_u64(0);
        let h: u128 = rng.random();
        let sender_key: u128 = rng.random();
        let receiver_key: u128 = h ^ sender_key;

        // Two messages.
        let first_message: Vec<u8> = (0..14).map(|_| rng.random()).collect();
        let second_message: Vec<u8> = (0..32).map(|_| rng.random()).collect();

        let (mut sender, mut receiver) = create_pair();

        sender.set_key(sender_key.to_be_bytes().to_vec()).unwrap();
        receiver
            .set_key(receiver_key.to_be_bytes().to_vec())
            .unwrap();

        tokio::try_join!(sender.setup(&mut ctx_a), receiver.setup(&mut ctx_b)).unwrap();

        // Compute and check first message.
        let sender_share = sender.compute(&first_message).unwrap();
        let receiver_share = receiver.compute(&first_message).unwrap();

        let tag = sender_share
            .iter()
            .zip(receiver_share.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        assert_eq!(tag, ghash_reference_impl(h, &first_message));

        // Compute and check second message.
        let sender_share = sender.compute(&second_message).unwrap();
        let receiver_share = receiver.compute(&second_message).unwrap();

        let tag = sender_share
            .iter()
            .zip(receiver_share.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        assert_eq!(tag, ghash_reference_impl(h, &second_message));
    }

    fn ghash_reference_impl(h: u128, message: &[u8]) -> Vec<u8> {
        let mut ghash = GhashReference::new(&h.to_be_bytes().into());
        ghash.update_padded(message);
        let mac = ghash.finalize();
        mac.to_vec()
    }
}
