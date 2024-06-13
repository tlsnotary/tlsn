use std::{collections::VecDeque, marker::PhantomData};

use async_trait::async_trait;

use mpz_garble::{value::ValueRef, Decode, DecodePrivate, Execute, Load, Memory};
use tracing::instrument;
use utils::id::NestedId;

use crate::{BlockCipher, BlockCipherCircuit, BlockCipherConfig, BlockCipherError, Visibility};

#[derive(Debug)]
struct State {
    private_execution_id: NestedId,
    public_execution_id: NestedId,
    preprocessed_private: VecDeque<BlockVars>,
    preprocessed_public: VecDeque<BlockVars>,
    key: Option<ValueRef>,
}

#[derive(Debug)]
struct BlockVars {
    msg: ValueRef,
    ciphertext: ValueRef,
}

/// An MPC block cipher.
#[derive(Debug)]
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
    /// Creates a new MPC block cipher.
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration for the block cipher.
    /// * `executor` - The executor to use for the MPC.
    pub fn new(config: BlockCipherConfig, executor: E) -> Self {
        let private_execution_id = NestedId::new(&config.id)
            .append_string("private")
            .append_counter();
        let public_execution_id = NestedId::new(&config.id)
            .append_string("public")
            .append_counter();
        Self {
            state: State {
                private_execution_id,
                public_execution_id,
                preprocessed_private: VecDeque::new(),
                preprocessed_public: VecDeque::new(),
                key: None,
            },
            executor,
            _cipher: PhantomData,
        }
    }

    fn define_block(&mut self, vis: Visibility) -> BlockVars {
        let (id, msg) = match vis {
            Visibility::Private => {
                let id = self
                    .state
                    .private_execution_id
                    .increment_in_place()
                    .to_string();
                let msg = self
                    .executor
                    .new_private_input::<C::BLOCK>(&format!("{}/msg", &id))
                    .expect("message is not defined");
                (id, msg)
            }
            Visibility::Blind => {
                let id = self
                    .state
                    .private_execution_id
                    .increment_in_place()
                    .to_string();
                let msg = self
                    .executor
                    .new_blind_input::<C::BLOCK>(&format!("{}/msg", &id))
                    .expect("message is not defined");
                (id, msg)
            }
            Visibility::Public => {
                let id = self
                    .state
                    .public_execution_id
                    .increment_in_place()
                    .to_string();
                let msg = self
                    .executor
                    .new_public_input::<C::BLOCK>(&format!("{}/msg", &id))
                    .expect("message is not defined");
                (id, msg)
            }
        };

        let ciphertext = self
            .executor
            .new_output::<C::BLOCK>(&format!("{}/ciphertext", &id))
            .expect("message is not defined");

        BlockVars { msg, ciphertext }
    }
}

#[async_trait]
impl<C, E> BlockCipher<C> for MpcBlockCipher<C, E>
where
    C: BlockCipherCircuit,
    E: Memory + Load + Execute + Decode + DecodePrivate + Send + Sync + Send,
{
    #[instrument(level = "trace", skip_all)]
    fn set_key(&mut self, key: ValueRef) {
        self.state.key = Some(key);
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn preprocess(
        &mut self,
        visibility: Visibility,
        count: usize,
    ) -> Result<(), BlockCipherError> {
        let key = self
            .state
            .key
            .clone()
            .ok_or_else(|| BlockCipherError::key_not_set())?;

        for _ in 0..count {
            let vars = self.define_block(visibility);

            self.executor
                .load(
                    C::circuit(),
                    &[key.clone(), vars.msg.clone()],
                    &[vars.ciphertext.clone()],
                )
                .await?;

            match visibility {
                Visibility::Private | Visibility::Blind => {
                    self.state.preprocessed_private.push_back(vars)
                }
                Visibility::Public => self.state.preprocessed_public.push_back(vars),
            }
        }

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn encrypt_private(&mut self, plaintext: Vec<u8>) -> Result<Vec<u8>, BlockCipherError> {
        let len = plaintext.len();
        let block: C::BLOCK = plaintext
            .try_into()
            .map_err(|_| BlockCipherError::invalid_message_length::<C>(len))?;

        let key = self
            .state
            .key
            .clone()
            .ok_or_else(|| BlockCipherError::key_not_set())?;

        let BlockVars { msg, ciphertext } =
            if let Some(vars) = self.state.preprocessed_private.pop_front() {
                vars
            } else {
                self.define_block(Visibility::Private)
            };

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

    #[instrument(level = "debug", skip_all, err)]
    async fn encrypt_blind(&mut self) -> Result<Vec<u8>, BlockCipherError> {
        let key = self
            .state
            .key
            .clone()
            .ok_or_else(|| BlockCipherError::key_not_set())?;

        let BlockVars { msg, ciphertext } =
            if let Some(vars) = self.state.preprocessed_private.pop_front() {
                vars
            } else {
                self.define_block(Visibility::Blind)
            };

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

    #[instrument(level = "debug", skip_all, err)]
    async fn encrypt_share(&mut self, plaintext: Vec<u8>) -> Result<Vec<u8>, BlockCipherError> {
        let len = plaintext.len();
        let block: C::BLOCK = plaintext
            .try_into()
            .map_err(|_| BlockCipherError::invalid_message_length::<C>(len))?;

        let key = self
            .state
            .key
            .clone()
            .ok_or_else(|| BlockCipherError::key_not_set())?;

        let BlockVars { msg, ciphertext } =
            if let Some(vars) = self.state.preprocessed_public.pop_front() {
                vars
            } else {
                self.define_block(Visibility::Public)
            };

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
