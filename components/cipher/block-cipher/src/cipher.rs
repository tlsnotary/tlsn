use std::marker::PhantomData;

use async_trait::async_trait;

use mpz_garble::{value::ValueRef, Decode, DecodePrivate, Execute, Memory};
use utils::id::NestedId;

use crate::{BlockCipher, BlockCipherCircuit, BlockCipherConfig, BlockCipherError};

struct State {
    execution_id: NestedId,
    key: Option<ValueRef>,
}

/// An MPC block cipher
pub struct MpcBlockCipher<C, E>
where
    C: BlockCipherCircuit,
    E: Memory + Execute + Decode + DecodePrivate + Send + Sync,
{
    state: State,

    executor: E,

    _cipher: PhantomData<C>,
}

impl<C, E> MpcBlockCipher<C, E>
where
    C: BlockCipherCircuit,
    E: Memory + Execute + Decode + DecodePrivate + Send + Sync,
{
    /// Creates a new MPC block cipher
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration for the block cipher
    /// * `executor` - The executor to use for the MPC
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "info", skip(executor))
    )]
    pub fn new(config: BlockCipherConfig, executor: E) -> Self {
        let execution_id = NestedId::new(&config.id).append_counter();
        Self {
            state: State {
                execution_id,
                key: None,
            },
            executor,
            _cipher: PhantomData,
        }
    }
}

#[async_trait]
impl<C, E> BlockCipher<C> for MpcBlockCipher<C, E>
where
    C: BlockCipherCircuit,
    E: Memory + Execute + Decode + DecodePrivate + Send + Sync + Send,
{
    #[cfg_attr(feature = "tracing", tracing::instrument(level = "info", skip(self)))]
    fn set_key(&mut self, key: ValueRef) {
        self.state.key = Some(key);
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "debug", skip(self, plaintext), err)
    )]
    async fn encrypt_private(&mut self, plaintext: Vec<u8>) -> Result<Vec<u8>, BlockCipherError> {
        let len = plaintext.len();
        let block: C::BLOCK = plaintext
            .try_into()
            .map_err(|_| BlockCipherError::InvalidInputLength(C::BLOCK_LEN, len))?;

        let key = self.state.key.clone().ok_or(BlockCipherError::KeyNotSet)?;

        let id = self.state.execution_id.increment_in_place().to_string();

        let msg = self
            .executor
            .new_private_input::<C::BLOCK>(&format!("{}/msg", &id))?;
        let ciphertext = self
            .executor
            .new_output::<C::BLOCK>(&format!("{}/ciphertext", &id))?;

        self.executor.assign(&msg, block)?;

        self.executor
            .execute(C::circuit(), &[key, msg], &[ciphertext.clone()])
            .await?;

        let mut outputs = self.executor.decode(&[ciphertext]).await?;

        let ciphertext: C::BLOCK = if let Ok(ciphertext) = outputs
            .pop()
            .expect("ciphertext should be present")
            .try_into()
        {
            ciphertext
        } else {
            panic!("ciphertext should be a block")
        };

        Ok(ciphertext.into())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "debug", skip(self), err)
    )]
    async fn encrypt_blind(&mut self) -> Result<Vec<u8>, BlockCipherError> {
        let key = self.state.key.clone().ok_or(BlockCipherError::KeyNotSet)?;

        let id = self.state.execution_id.increment_in_place().to_string();

        let msg = self
            .executor
            .new_blind_input::<C::BLOCK>(&format!("{}/msg", &id))?;
        let ciphertext = self
            .executor
            .new_output::<C::BLOCK>(&format!("{}/ciphertext", &id))?;

        self.executor
            .execute(C::circuit(), &[key, msg], &[ciphertext.clone()])
            .await?;

        let mut outputs = self.executor.decode(&[ciphertext]).await?;

        let ciphertext: C::BLOCK = if let Ok(ciphertext) = outputs
            .pop()
            .expect("ciphertext should be present")
            .try_into()
        {
            ciphertext
        } else {
            panic!("ciphertext should be a block")
        };

        Ok(ciphertext.into())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "debug", skip(self, plaintext), err)
    )]
    async fn encrypt_share(&mut self, plaintext: Vec<u8>) -> Result<Vec<u8>, BlockCipherError> {
        let len = plaintext.len();
        let block: C::BLOCK = plaintext
            .try_into()
            .map_err(|_| BlockCipherError::InvalidInputLength(C::BLOCK_LEN, len))?;

        let key = self.state.key.clone().ok_or(BlockCipherError::KeyNotSet)?;

        let id = self.state.execution_id.increment_in_place().to_string();

        let msg = self
            .executor
            .new_public_input::<C::BLOCK>(&format!("{}/msg", &id))?;
        let ciphertext = self
            .executor
            .new_output::<C::BLOCK>(&format!("{}/ciphertext", &id))?;

        self.executor.assign(&msg, block)?;

        self.executor
            .execute(C::circuit(), &[key, msg], &[ciphertext.clone()])
            .await?;

        let mut outputs = self.executor.decode_shared(&[ciphertext]).await?;

        let share: C::BLOCK =
            if let Ok(share) = outputs.pop().expect("share should be present").try_into() {
                share
            } else {
                panic!("share should be a block")
            };

        Ok(share.into())
    }
}
