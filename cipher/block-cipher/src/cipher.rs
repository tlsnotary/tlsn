use std::{marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use futures::lock::Mutex;

use mpc_circuits::{Value, WireGroup};
use mpc_garble::{exec::dual::DEExecute, factory::GCFactoryError};
use mpc_garble_core::{
    exec::dual::{DualExConfig, DualExConfigBuilder},
    ActiveEncodedInput, ChaChaEncoder, Encoder, FullEncodedInput, FullInputSet,
};
use utils_aio::factory::AsyncFactory;

use crate::{
    config::Role, BlockCipher, BlockCipherCircuit, BlockCipherCircuitSuite, BlockCipherConfig,
    BlockCipherError, BlockCipherLabels, BlockCipherShareCircuit,
};

pub struct State {
    execution_id: usize,
    encoder: Option<Arc<Mutex<ChaChaEncoder>>>,
    labels: Option<BlockCipherLabels>,
}

pub struct DEBlockCipher<C, DEF, DE>
where
    C: BlockCipherCircuitSuite,
    DEF: AsyncFactory<DE, Config = DualExConfig, Error = GCFactoryError>,
    DE: DEExecute,
{
    config: BlockCipherConfig,
    state: State,

    de_factory: DEF,

    _cipher: PhantomData<C>,
    _de: PhantomData<DE>,
}

impl<C, DEF, DE> DEBlockCipher<C, DEF, DE>
where
    C: BlockCipherCircuitSuite,
    DEF: AsyncFactory<DE, Config = DualExConfig, Error = GCFactoryError> + Send,
    DE: DEExecute + Send,
{
    pub fn new(config: BlockCipherConfig, de_factory: DEF) -> Self {
        Self {
            config,
            state: State {
                execution_id: 0,
                encoder: None,
                labels: None,
            },
            de_factory,
            _cipher: PhantomData,
            _de: PhantomData,
        }
    }
}

#[async_trait]
impl<C, DEF, DE> BlockCipher<C> for DEBlockCipher<C, DEF, DE>
where
    C: BlockCipherCircuitSuite,
    DEF: AsyncFactory<DE, Config = DualExConfig, Error = GCFactoryError> + Send,
    DE: DEExecute + Send,
{
    /// Sets the key input labels for the block cipher.
    ///
    /// * `labels`: The labels to use for the key input.
    fn set_keys(&mut self, labels: BlockCipherLabels) {
        self.state.labels = Some(labels);
    }

    /// Sets the encoder used to generate the input labels
    /// used during 2PC.
    fn set_encoder(&mut self, encoder: Arc<Mutex<ChaChaEncoder>>) {
        self.state.encoder = Some(encoder);
    }

    /// Encrypts the given plaintext.
    ///
    /// Returns the ciphertext
    ///
    /// * `plaintext` - The plaintext to encrypt
    async fn encrypt_private(&mut self, plaintext: Vec<u8>) -> Result<Vec<u8>, BlockCipherError> {
        let labels = self
            .state
            .labels
            .clone()
            .ok_or(BlockCipherError::KeysNotSet)?;

        let encoder = self
            .state
            .encoder
            .as_mut()
            .ok_or(BlockCipherError::EncoderNotSet)?;

        // Compute instance id
        let id = format!("{}/{}", self.config.id, self.state.execution_id);

        self.state.execution_id += 1;

        let cipher = C::BlockCipherCircuit::default();

        if plaintext.len() != C::BLOCK_SIZE {
            return Err(BlockCipherError::InvalidInputLength(
                C::BLOCK_SIZE,
                plaintext.len(),
            ));
        }

        let de_config = DualExConfigBuilder::default()
            .id(id.clone())
            .circ(cipher.circuit())
            .build()
            .expect("DualExConfig should be valid");
        let de = self.de_factory.create(id, de_config).await?;

        let key_input = cipher.key();
        let text_input = cipher
            .text()
            .to_value(plaintext)
            .expect("plaintext is valid length");

        let mut encoder = encoder.lock().await;
        let text_labels = FullEncodedInput::from_labels(
            text_input.group().clone(),
            encoder.encode(self.config.encoder_default_stream_id, text_input.group()),
        )
        .expect("Text labels should be valid");
        drop(encoder);

        let key_full_labels = FullEncodedInput::from_labels(key_input.clone(), labels.key_full)
            .expect("Key labels should be valid");
        let key_active_labels = ActiveEncodedInput::from_labels(key_input, labels.key_active)
            .expect("Key labels should be valid");

        let gen_labels = FullInputSet::new(vec![key_full_labels, text_labels])
            .expect("Circuit input should only be key and text");
        let gen_inputs = vec![text_input.clone()];
        let ot_send_inputs = vec![];
        let ot_receive_inputs = vec![text_input];
        let cached_labels = vec![key_active_labels];

        let output = de
            .execute(
                gen_labels,
                gen_inputs,
                ot_send_inputs,
                ot_receive_inputs,
                cached_labels,
            )
            .await?;

        let Value::Bytes(ciphertext) = output[cipher.ciphertext().index()].value().clone() else {
            panic!("Ciphertext should be bytes");
        };

        Ok(ciphertext)
    }

    /// Encrypts a plaintext provided by the other party
    ///
    /// Returns the ciphertext
    async fn encrypt_blind(&mut self) -> Result<Vec<u8>, BlockCipherError> {
        let labels = self
            .state
            .labels
            .clone()
            .ok_or(BlockCipherError::KeysNotSet)?;

        let encoder = self
            .state
            .encoder
            .clone()
            .ok_or(BlockCipherError::EncoderNotSet)?;

        // Instance ID / Execution ID
        let id = format!("{}/{}", self.config.id, self.state.execution_id);
        self.state.execution_id += 1;

        let cipher = C::BlockCipherCircuit::default();

        let de_config = DualExConfigBuilder::default()
            .id(id.clone())
            .circ(cipher.circuit())
            .build()
            .expect("DualExConfig should be valid");
        let de = self.de_factory.create(id, de_config).await?;

        let key_input = cipher.key();
        let text_input = cipher.text();

        let mut encoder = encoder.lock().await;
        let text_labels = FullEncodedInput::from_labels(
            text_input.clone(),
            encoder.encode(self.config.encoder_default_stream_id, &text_input),
        )
        .expect("Text labels should be valid");
        drop(encoder);

        let key_full_labels = FullEncodedInput::from_labels(key_input.clone(), labels.key_full)
            .expect("Key labels should be valid");
        let key_active_labels = ActiveEncodedInput::from_labels(key_input, labels.key_active)
            .expect("Key labels should be valid");

        let gen_labels = FullInputSet::new(vec![key_full_labels, text_labels])
            .expect("Circuit input should only be key and text");
        let gen_inputs = vec![];
        let ot_send_inputs = vec![text_input];
        let ot_receive_inputs = vec![];
        let cached_labels = vec![key_active_labels];

        let output = de
            .execute(
                gen_labels,
                gen_inputs,
                ot_send_inputs,
                ot_receive_inputs,
                cached_labels,
            )
            .await?;

        let Value::Bytes(ciphertext) = output[cipher.ciphertext().index()].value().clone() else {
            panic!("Ciphertext should be bytes");
        };

        Ok(ciphertext)
    }

    /// Encrypts a plaintext provided by both parties. Fails if the
    /// plaintext provided by both parties does not match.
    ///
    /// Returns the additive share of the ciphertext
    ///
    /// * `plaintext` - The plaintext to encrypt
    /// * `mask` - The additive share of the mask to use
    async fn encrypt_share(
        &mut self,
        plaintext: Vec<u8>,
        mask: Vec<u8>,
    ) -> Result<Vec<u8>, BlockCipherError> {
        let labels = self
            .state
            .labels
            .clone()
            .ok_or(BlockCipherError::KeysNotSet)?;

        let encoder = self
            .state
            .encoder
            .clone()
            .ok_or(BlockCipherError::EncoderNotSet)?;

        // Instance ID / Execution ID
        let id = format!("{}/{}", self.config.id, self.state.execution_id);
        self.state.execution_id += 1;

        let cipher = C::ShareCircuit::default();

        if plaintext.len() != C::BLOCK_SIZE {
            return Err(BlockCipherError::InvalidInputLength(
                C::BLOCK_SIZE,
                plaintext.len(),
            ));
        }

        if mask.len() != C::BLOCK_SIZE {
            return Err(BlockCipherError::InvalidInputLength(
                C::BLOCK_SIZE,
                plaintext.len(),
            ));
        }

        let de_config = DualExConfigBuilder::default()
            .id(id.clone())
            .circ(cipher.circuit())
            .build()
            .expect("DualExConfig should be valid");
        let de = self.de_factory.create(id, de_config).await?;

        let key_input = cipher.key();
        let text_input = cipher
            .text()
            .to_value(plaintext)
            .expect("plaintext is valid length");
        let mask_leader_input = cipher.mask_0();
        let mask_follower_input = cipher.mask_1();

        let mut encoder = encoder.lock().await;
        let text_labels = FullEncodedInput::from_labels(
            text_input.group().clone(),
            encoder.encode(self.config.encoder_default_stream_id, text_input.group()),
        )
        .expect("Text labels should be valid");
        let mask_leader_labels = FullEncodedInput::from_labels(
            mask_leader_input.clone(),
            encoder.encode(self.config.encoder_default_stream_id, &mask_leader_input),
        )
        .expect("Mask leader labels should be valid");
        let mask_follower_labels = FullEncodedInput::from_labels(
            mask_follower_input.clone(),
            encoder.encode(self.config.encoder_default_stream_id, &mask_follower_input),
        )
        .expect("Mask follower labels should be valid");
        drop(encoder);

        let key_full_labels = FullEncodedInput::from_labels(key_input.clone(), labels.key_full)
            .expect("Key labels should be valid");
        let key_active_labels = ActiveEncodedInput::from_labels(key_input, labels.key_active)
            .expect("Key labels should be valid");

        let gen_labels = FullInputSet::new(vec![
            key_full_labels,
            text_labels,
            mask_leader_labels,
            mask_follower_labels,
        ])
        .expect("Circuit inputs should be complete");

        let (gen_inputs, ot_send_inputs, ot_receive_inputs) = match self.config.role {
            Role::Leader => {
                let mask_leader_input = mask_leader_input
                    .to_value(mask.clone())
                    .expect("mask should be valid length");

                (
                    vec![text_input.clone(), mask_leader_input.clone()],
                    vec![mask_follower_input],
                    vec![mask_leader_input],
                )
            }
            Role::Follower => {
                let mask_follower_input = mask_follower_input
                    .to_value(mask.clone())
                    .expect("mask is valid length");

                (
                    vec![text_input.clone(), mask_follower_input.clone()],
                    vec![mask_leader_input],
                    vec![mask_follower_input],
                )
            }
        };

        let cached_labels = vec![key_active_labels];

        let mut output = de
            .execute(
                gen_labels,
                gen_inputs,
                ot_send_inputs,
                ot_receive_inputs,
                cached_labels,
            )
            .await?;

        let Value::Bytes(masked_ciphertext) = output.remove(cipher.masked_ciphertext().index()).value().clone() else {
            panic!("Masked ciphertext should be bytes");
        };

        // Masked ciphertext C_MASKED = C + MASK_LEADER + MASK_FOLLOWER
        // Leader share = C_MASKED - MASK_LEADER
        // Follower share = MASK_FOLLOWER
        let share = match self.config.role {
            Role::Leader => masked_ciphertext
                .into_iter()
                .zip(mask.into_iter())
                .map(|(a, b)| a ^ b)
                .collect::<Vec<_>>(),
            Role::Follower => mask,
        };

        Ok(share)
    }
}
