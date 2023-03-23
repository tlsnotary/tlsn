use std::{marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use futures::{lock::Mutex, SinkExt};
use mpc_circuits::{circuits::nbyte_xor, BitOrder, WireGroup};

use crate::{
    cipher::{CtrCircuit, CtrCircuitSuite, CtrShareCircuit},
    config::{CounterModeConfigBuilder, StreamCipherConfig},
    counter_block::KeyBlockLabels,
    counter_mode::CtrMode,
    msg::{PlaintextLabels, StreamCipherMessage},
    utils::block_count,
    Role, StreamCipherChannel, StreamCipherError, StreamCipherFollower, StreamCipherLabels,
};
use mpc_garble::{
    exec::{dual::DEExecute, zk::Verify},
    factory::GCFactoryError,
};
use mpc_garble_core::{
    exec::{
        dual::{DESummary, DualExConfig},
        zk::{VerifierConfig, VerifierConfigBuilder},
    },
    ActiveEncodedInput, ChaChaEncoder, Encoder, FullEncodedInput, FullInputSet, FullLabels, Label,
    LabelPair,
};
use utils_aio::factory::AsyncFactory;

#[derive(Default)]
pub struct State {
    pub(super) execution_id: usize,
    pub(super) encoder: Option<Arc<Mutex<ChaChaEncoder>>>,
    pub(super) labels: Option<StreamCipherLabels>,
}

pub struct DEStreamCipherFollower<C, DEF, DE, VF, V>
where
    C: CtrCircuitSuite,
    DEF: AsyncFactory<DE, Config = DualExConfig, Error = GCFactoryError> + Send + Clone,
    DE: DEExecute + Send,
    VF: AsyncFactory<V, Config = VerifierConfig, Error = GCFactoryError> + Send + Clone,
    V: Verify + Send,
{
    config: StreamCipherConfig,
    state: State,
    channel: StreamCipherChannel,

    ctr_mode: CtrMode<C, DEF, DE>,

    verifier_factory: VF,

    _verifier: PhantomData<V>,
}

impl<C, DEF, DE, VF, V> DEStreamCipherFollower<C, DEF, DE, VF, V>
where
    C: CtrCircuitSuite,
    DEF: AsyncFactory<DE, Config = DualExConfig, Error = GCFactoryError> + Send + Clone,
    DE: DEExecute + Send,
    VF: AsyncFactory<V, Config = VerifierConfig, Error = GCFactoryError> + Send + Clone,
    V: Verify + Send,
{
    /// Create a new stream cipher
    pub fn new(
        config: StreamCipherConfig,
        channel: StreamCipherChannel,
        de_factory: DEF,
        verifier_factory: VF,
    ) -> DEStreamCipherFollower<C, DEF, DE, VF, V> {
        let ctr_mode_config = CounterModeConfigBuilder::default()
            .id(format!("{}/ctr", config.id))
            .role(Role::Follower)
            .start_ctr(config.start_ctr)
            .concurrency(config.concurrency)
            .build()
            .expect("CounterMode config should be valid");

        DEStreamCipherFollower {
            config,
            state: State::default(),
            channel,
            ctr_mode: CtrMode::new(ctr_mode_config, de_factory),
            verifier_factory,
            _verifier: PhantomData,
        }
    }

    async fn verify_plaintext(
        &mut self,
        plaintext_labels: FullLabels,
        keystream_labels: FullLabels,
        ciphertext: Vec<u8>,
    ) -> Result<(), StreamCipherError> {
        let circ = nbyte_xor(ciphertext.len());

        let id = format!("{}/{}", self.config.id, self.state.execution_id);
        self.state.execution_id += 1;

        let verifier_config = VerifierConfigBuilder::default()
            .id(id.clone())
            .circ(circ.clone())
            .build()
            .expect("Verifier config should be valid");

        let verifier = self.verifier_factory.create(id, verifier_config).await?;

        let input_plaintext =
            FullEncodedInput::from_labels(circ.inputs()[0].clone(), plaintext_labels)
                .expect("Labels should be valid");

        let input_keystream =
            FullEncodedInput::from_labels(circ.inputs()[1].clone(), keystream_labels)
                .expect("Labels should be valid");

        let expected_output = circ.outputs()[0]
            .clone()
            .to_value(ciphertext)
            .expect("Ciphertext should be valid");

        let gen_labels = FullInputSet::new(vec![input_plaintext, input_keystream])
            .expect("Inputs should be valid");

        _ = verifier
            .verify(
                gen_labels,
                vec![],
                vec![circ.inputs()[0].clone()],
                vec![expected_output],
            )
            .await?;

        Ok(())
    }

    async fn build_plaintext_labels(
        &mut self,
        len: usize,
    ) -> Result<FullLabels, StreamCipherError> {
        let encoder = self
            .state
            .encoder
            .clone()
            .ok_or(StreamCipherError::EncoderNotSet)?;
        let mut encoder = encoder.lock().await;
        let delta = encoder.get_delta();
        let stream = encoder.get_stream(self.config.encoder_text_stream_id);
        let labels = FullLabels::generate(stream, len * 8, Some(delta));
        drop(encoder);

        Ok(labels)
    }

    async fn build_ctr_share_labels(&mut self) -> Result<KeyBlockLabels, StreamCipherError> {
        let cipher = C::CtrShareCircuit::default();

        let cipher_labels = self
            .state
            .labels
            .clone()
            .ok_or(StreamCipherError::KeysNotSet)?;

        let encoder = self
            .state
            .encoder
            .clone()
            .ok_or(StreamCipherError::EncoderNotSet)?;

        let full_key_labels = FullEncodedInput::from_labels(cipher.key(), cipher_labels.key_full)
            .expect("Key labels should be valid");
        let full_iv_labels = FullEncodedInput::from_labels(cipher.iv(), cipher_labels.iv_full)
            .expect("IV labels should be valid");
        let active_key_labels =
            ActiveEncodedInput::from_active_labels(cipher.key(), cipher_labels.key_active)
                .expect("Key labels should be valid");
        let active_iv_labels =
            ActiveEncodedInput::from_active_labels(cipher.iv(), cipher_labels.iv_active)
                .expect("IV labels should be valid");

        let input_nonce = cipher.nonce();
        let input_ctr = cipher.counter();
        let input_mask_0 = cipher.mask_0();
        let input_mask_1 = cipher.mask_1();

        let encoder_stream_id = self.config.encoder_default_stream_id;
        let mut encoder = encoder.lock().await;
        let nonce_labels = encoder.encode(encoder_stream_id, &input_nonce);
        let ctr_labels = encoder.encode(encoder_stream_id, &input_ctr);
        let mask_0_labels = encoder.encode(encoder_stream_id, &input_mask_0);
        let mask_1_labels = encoder.encode(encoder_stream_id, &input_mask_1);
        drop(encoder);

        let nonce_labels = FullEncodedInput::from_labels(input_nonce, nonce_labels)
            .expect("Nonce labels should be valid");
        let ctr_labels = FullEncodedInput::from_labels(input_ctr, ctr_labels)
            .expect("Counter labels should be valid");
        let mask_0_labels = FullEncodedInput::from_labels(input_mask_0, mask_0_labels)
            .expect("Mask 0 labels should be valid");
        let mask_1_labels = FullEncodedInput::from_labels(input_mask_1, mask_1_labels)
            .expect("Mask 1 labels should be valid");

        let gen_labels = FullInputSet::new(vec![
            full_key_labels,
            full_iv_labels,
            nonce_labels,
            ctr_labels,
            mask_0_labels,
            mask_1_labels,
        ])
        .expect("Label set should be valid");

        Ok(KeyBlockLabels {
            gen_labels,
            active_key_labels: active_key_labels.clone(),
            active_iv_labels: active_iv_labels.clone(),
        })
    }

    async fn build_ctr_labels(
        &mut self,
        msg_len: usize,
        use_dedicated_stream: bool,
    ) -> Result<Vec<KeyBlockLabels>, StreamCipherError> {
        let cipher = C::CtrCircuit::default();

        let cipher_labels = self
            .state
            .labels
            .clone()
            .ok_or(StreamCipherError::KeysNotSet)?;

        let encoder = self
            .state
            .encoder
            .clone()
            .ok_or(StreamCipherError::EncoderNotSet)?;

        let block_count = block_count(msg_len, C::CtrCircuit::BLOCK_SIZE);

        let full_key_labels = FullEncodedInput::from_labels(cipher.key(), cipher_labels.key_full)
            .expect("Key labels should be valid");
        let full_iv_labels = FullEncodedInput::from_labels(cipher.iv(), cipher_labels.iv_full)
            .expect("IV labels should be valid");
        let active_key_labels =
            ActiveEncodedInput::from_active_labels(cipher.key(), cipher_labels.key_active)
                .expect("Key labels should be valid");
        let active_iv_labels =
            ActiveEncodedInput::from_active_labels(cipher.iv(), cipher_labels.iv_active)
                .expect("IV labels should be valid");

        // If we're recording, we need to use the dedicated text stream ID
        let text_stream_id = if use_dedicated_stream {
            self.config.encoder_text_stream_id
        } else {
            self.config.encoder_default_stream_id
        };

        let mut encoder = encoder.lock().await;

        // Generate labels for all blocks except the last one
        let mut text_labels = (0..block_count - 1)
            .map(|_| {
                FullEncodedInput::from_labels(
                    cipher.input_text(),
                    encoder.encode(text_stream_id, &cipher.input_text()),
                )
                .expect("Text labels should be valid")
            })
            .collect::<Vec<_>>();

        // Calculate how many padding bytes we need to add to the last block
        let padding_len = (C::CtrCircuit::BLOCK_SIZE - msg_len % C::CtrCircuit::BLOCK_SIZE)
            % C::CtrCircuit::BLOCK_SIZE;

        text_labels.push(
            FullEncodedInput::from_labels(
                cipher.input_text(),
                encoder.encode_padded(text_stream_id, &cipher.input_text(), padding_len * 8),
            )
            .expect("Text labels should be valid"),
        );

        let nonce_labels = FullEncodedInput::from_labels(
            cipher.nonce(),
            encoder.encode(self.config.encoder_default_stream_id, &cipher.nonce()),
        )
        .expect("Nonce labels should be valid");
        let ctr_labels = (0..block_count)
            .map(|_| {
                FullEncodedInput::from_labels(
                    cipher.counter(),
                    encoder.encode(self.config.encoder_default_stream_id, &cipher.counter()),
                )
                .expect("Counter labels should be valid")
            })
            .collect::<Vec<_>>();
        drop(encoder);

        let gen_labels = text_labels
            .into_iter()
            .zip(ctr_labels.into_iter())
            .map(|(text_labels, ctr_labels)| {
                let gen_labels = FullInputSet::new(vec![
                    full_key_labels.clone(),
                    full_iv_labels.clone(),
                    text_labels,
                    nonce_labels.clone(),
                    ctr_labels,
                ])
                .expect("Label set should be valid");

                KeyBlockLabels {
                    gen_labels,
                    active_key_labels: active_key_labels.clone(),
                    active_iv_labels: active_iv_labels.clone(),
                }
            })
            .collect::<Vec<_>>();

        Ok(gen_labels)
    }
}

#[async_trait]
impl<C, DEF, DE, VF, V> StreamCipherFollower<C> for DEStreamCipherFollower<C, DEF, DE, VF, V>
where
    C: CtrCircuitSuite,
    DEF: AsyncFactory<DE, Config = DualExConfig, Error = GCFactoryError> + Send + Clone,
    DE: DEExecute + Send,
    VF: AsyncFactory<V, Config = VerifierConfig, Error = GCFactoryError> + Send + Clone,
    V: Verify + Send,
{
    fn set_keys(&mut self, labels: StreamCipherLabels) {
        self.state.labels = Some(labels);
    }

    fn set_encoder(&mut self, encoder: Arc<Mutex<ChaChaEncoder>>) {
        self.state.encoder = Some(encoder);
    }

    async fn encrypt_public(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext: Vec<u8>,
        record: bool,
    ) -> Result<Vec<u8>, StreamCipherError> {
        let len = plaintext.len();
        let labels = self.build_ctr_labels(plaintext.len(), record).await?;

        let (ciphertext, _) = self
            .ctr_mode
            .apply_keystream(explicit_nonce, Some(plaintext), len, labels, false)
            .await?;

        Ok(ciphertext)
    }

    async fn encrypt_blind(
        &mut self,
        explicit_nonce: Vec<u8>,
        len: usize,
        record: bool,
    ) -> Result<Vec<u8>, StreamCipherError> {
        let labels = self.build_ctr_labels(len, record).await?;

        let (ciphertext, _) = self
            .ctr_mode
            .apply_keystream(explicit_nonce, None, len, labels, true)
            .await?;

        Ok(ciphertext)
    }

    async fn decrypt_public(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        record: bool,
    ) -> Result<Vec<u8>, StreamCipherError> {
        let len = ciphertext.len();
        let labels = self.build_ctr_labels(ciphertext.len(), false).await?;

        let (plaintext, _) = self
            .ctr_mode
            .apply_keystream(explicit_nonce, Some(ciphertext.clone()), len, labels, false)
            .await?;

        if record {
            let plaintext_labels = self
                .build_plaintext_labels(plaintext.len())
                .await?
                .select(&plaintext.clone().into(), BitOrder::Msb0)
                .expect("Bytes should be a valid value type")
                .iter()
                .collect::<Vec<Label>>();

            // Send plaintext labels directly to the leader
            self.channel
                .send(StreamCipherMessage::PlaintextLabels(PlaintextLabels {
                    labels: plaintext_labels,
                }))
                .await?;
        }

        Ok(plaintext)
    }

    async fn decrypt_blind(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        record: bool,
    ) -> Result<(), StreamCipherError> {
        let len = ciphertext.len();
        let labels = self.build_ctr_labels(ciphertext.len(), false).await?;

        let (_, summaries) = self
            .ctr_mode
            .apply_keystream(explicit_nonce, None, len, labels, true)
            .await?;

        if record {
            let plaintext_labels = self.build_plaintext_labels(len).await?;
            let keystream_labels = extract_keystream_labels::<C>(len, summaries);

            // Verify that the leader's plaintext encrypts to the ciphertext
            self.verify_plaintext(plaintext_labels, keystream_labels, ciphertext)
                .await?;
        }

        Ok(())
    }

    async fn share_keystream_block(
        &mut self,
        explicit_nonce: Vec<u8>,
        ctr: u32,
    ) -> Result<Vec<u8>, StreamCipherError> {
        let labels = self.build_ctr_share_labels().await?;

        self.ctr_mode
            .share_keystream_block(explicit_nonce, ctr, labels)
            .await
    }
}

/// Extracts keystream labels from execution summaries.
fn extract_keystream_labels<C: CtrCircuitSuite>(
    len: usize,
    summaries: Vec<DESummary>,
) -> FullLabels {
    let cipher = C::CtrCircuit::default();
    let input_text_index = cipher.input_text().index();
    let output_text_index = cipher.output_text().index();

    let mut keystream_labels = Vec::with_capacity(summaries.len() * C::CtrCircuit::BLOCK_SIZE);
    for summary in summaries {
        let input_labels = summary.get_generator_summary().input_labels();
        let output_labels = summary.get_generator_summary().output_labels();

        let input_text_labels = input_labels[input_text_index].clone().into_labels();
        let output_text_labels = output_labels[output_text_index].clone().into_labels();

        let key_block_labels = (input_text_labels ^ output_text_labels)
            .iter()
            .collect::<Vec<LabelPair>>();

        keystream_labels.extend(key_block_labels);
    }
    keystream_labels.truncate(len * 8);

    FullLabels::new_from_pairs(keystream_labels)
}
