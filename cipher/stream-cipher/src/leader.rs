use std::{marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use futures::{lock::Mutex, SinkExt, StreamExt};
use mpc_circuits::{circuits::nbyte_xor, WireGroup};
use rand::RngCore;

use crate::{
    cipher::{CtrCircuit, CtrCircuitSuite, CtrShareCircuit},
    config::{CounterModeConfigBuilder, StreamCipherConfig},
    counter_block::KeyBlockLabels,
    counter_mode::CtrMode,
    msg::{PlaintextLabels, StreamCipherMessage},
    utils::block_count,
    MessageTranscript, Role, StreamCipherChannel, StreamCipherError, StreamCipherLabels,
    StreamCipherLeader, TranscriptSink,
};
use mpc_aio::protocol::garble::{
    exec::{dual::DEExecute, zk::Prove},
    factory::GCFactoryError,
};
use mpc_core::garble::{
    exec::{
        dual::{DESummary, DualExConfig},
        zk::{ProverConfig, ProverConfigBuilder},
    },
    ActiveEncodedInput, ActiveLabels, ChaChaEncoder, Encoder, FullEncodedInput, FullInputSet,
    Label,
};
use utils_aio::{expect_msg_or_err, factory::AsyncFactory};

#[derive(Default)]
pub struct State {
    pub(super) execution_id: usize,
    pub(super) encoder: Option<Arc<Mutex<ChaChaEncoder>>>,
    pub(super) labels: Option<StreamCipherLabels>,
    pub(super) transcript_sink: Option<TranscriptSink>,
}

pub struct DEStreamCipherLeader<C, DEF, DE, PF, P>
where
    C: CtrCircuitSuite,
    DEF: AsyncFactory<DE, Config = DualExConfig, Error = GCFactoryError> + Clone,
    DE: DEExecute,
    PF: AsyncFactory<P, Config = ProverConfig, Error = GCFactoryError> + Clone,
    P: Prove,
{
    config: StreamCipherConfig,
    state: State,
    channel: StreamCipherChannel,

    ctr_mode: CtrMode<C, DEF, DE>,

    prover_factory: PF,

    _prover: PhantomData<P>,
}

impl<C, DEF, DE, PF, P> DEStreamCipherLeader<C, DEF, DE, PF, P>
where
    C: CtrCircuitSuite,
    DEF: AsyncFactory<DE, Config = DualExConfig, Error = GCFactoryError> + Clone + Send,
    DE: DEExecute,
    PF: AsyncFactory<P, Config = ProverConfig, Error = GCFactoryError> + Clone + Send,
    P: Prove,
{
    /// Create a new stream cipher
    pub fn new(
        config: StreamCipherConfig,
        channel: StreamCipherChannel,
        de_factory: DEF,
        prover_factory: PF,
    ) -> DEStreamCipherLeader<C, DEF, DE, PF, P> {
        let ctr_mode_config = CounterModeConfigBuilder::default()
            .id(format!("{}/ctr", config.id))
            .role(Role::Leader)
            .start_ctr(config.start_ctr)
            .concurrency(config.concurrency)
            .build()
            .expect("CounterMode config should be valid");

        DEStreamCipherLeader {
            config,
            state: State::default(),
            channel,
            ctr_mode: CtrMode::new(ctr_mode_config, de_factory),
            prover_factory,
            _prover: PhantomData,
        }
    }

    /// Writes message and corresponding active labels to transcript
    async fn write_to_transcript(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext: Vec<u8>,
        plaintext_labels: Vec<Label>,
        ciphertext: Vec<u8>,
    ) -> Result<(), StreamCipherError> {
        let transcript =
            MessageTranscript::new(explicit_nonce, plaintext, plaintext_labels, ciphertext);

        if let Some(sink) = &mut self.state.transcript_sink {
            sink.send(transcript).await?;
        }

        Ok(())
    }

    /// Proves to the follower that the plaintext encrypts to the expected ciphertext
    ///
    /// Returns the plaintext labels retrieved via OT
    async fn prove_ciphertext(
        &mut self,
        plaintext: Vec<u8>,
        key_stream_labels: ActiveLabels,
    ) -> Result<Vec<Label>, StreamCipherError> {
        let circ = nbyte_xor(plaintext.len());

        let id = format!("{}/{}", self.config.id, self.state.execution_id);
        self.state.execution_id += 1;

        let prover_config = ProverConfigBuilder::default()
            .id(id.clone())
            .circ(circ.clone())
            .build()
            .expect("Prover config should be valid");

        let prover = self.prover_factory.create(id, prover_config).await?;

        let input_plaintext = circ.inputs()[0]
            .clone()
            .to_value(plaintext)
            .expect("Input should be valid");

        let input_key_stream =
            ActiveEncodedInput::from_active_labels(circ.inputs()[1].clone(), key_stream_labels)
                .expect("Key stream labels should be valid");

        let summary = prover
            .prove_and_summarize(vec![input_plaintext], vec![input_key_stream])
            .await?;

        let plaintext_labels = summary.get_evaluator_summary().input_labels()[0]
            .iter()
            .collect::<Vec<_>>();

        Ok(plaintext_labels)
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

        let encoder_stream_id = self.config.encoder_default_stream_id;
        let mut encoder = encoder.lock().await;
        let nonce_labels = encoder.encode(encoder_stream_id, &cipher.nonce());
        let ctr_labels = encoder.encode(encoder_stream_id, &cipher.counter());
        let mask_0_labels = encoder.encode(encoder_stream_id, &cipher.mask_0());
        let mask_1_labels = encoder.encode(encoder_stream_id, &cipher.mask_1());
        drop(encoder);

        let nonce_labels = FullEncodedInput::from_labels(cipher.nonce(), nonce_labels)
            .expect("Nonce labels should be valid");
        let ctr_labels = FullEncodedInput::from_labels(cipher.counter(), ctr_labels)
            .expect("Counter labels should be valid");
        let mask_0_labels = FullEncodedInput::from_labels(cipher.mask_0(), mask_0_labels)
            .expect("Mask 0 labels should be valid");
        let mask_1_labels = FullEncodedInput::from_labels(cipher.mask_1(), mask_1_labels)
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

        let encoder_stream_id = self.config.encoder_default_stream_id;
        let mut encoder = encoder.lock().await;
        let text_labels = (0..block_count)
            .map(|_| {
                FullEncodedInput::from_labels(
                    cipher.input_text(),
                    encoder.encode(encoder_stream_id, &cipher.input_text()),
                )
                .expect("Text labels should be valid")
            })
            .collect::<Vec<_>>();
        let nonce_labels = FullEncodedInput::from_labels(
            cipher.nonce(),
            encoder.encode(encoder_stream_id, &cipher.nonce()),
        )
        .expect("Nonce labels should be valid");
        let ctr_labels = (0..block_count)
            .map(|_| {
                FullEncodedInput::from_labels(
                    cipher.counter(),
                    encoder.encode(encoder_stream_id, &cipher.counter()),
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

    async fn encrypt(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext: Vec<u8>,
        record: bool,
        private: bool,
    ) -> Result<Vec<u8>, StreamCipherError> {
        let len = plaintext.len();
        let labels = self.build_ctr_labels(len).await?;

        let (ciphertext, summaries) = self
            .ctr_mode
            .apply_key_stream(
                explicit_nonce.clone(),
                Some(plaintext.clone()),
                len,
                labels,
                private,
            )
            .await?;

        if record {
            let plaintext_labels = extract_plaintext_labels::<C>(len, summaries);

            self.write_to_transcript(
                explicit_nonce,
                plaintext,
                plaintext_labels.into_iter().collect(),
                ciphertext.clone(),
            )
            .await?;
        }

        Ok(ciphertext)
    }
}

#[async_trait]
impl<C, DEF, DE, PF, P> StreamCipherLeader<C> for DEStreamCipherLeader<C, DEF, DE, PF, P>
where
    C: CtrCircuitSuite,
    DEF: AsyncFactory<DE, Config = DualExConfig, Error = GCFactoryError> + Clone + Send,
    DE: DEExecute + Send,
    PF: AsyncFactory<P, Config = ProverConfig, Error = GCFactoryError> + Clone + Send,
    P: Prove + Send,
{
    fn set_keys(&mut self, labels: StreamCipherLabels) {
        self.state.labels = Some(labels);
    }

    fn set_encoder(&mut self, encoder: Arc<Mutex<ChaChaEncoder>>) {
        self.state.encoder = Some(encoder);
    }

    fn set_transcript_sink(&mut self, sink: TranscriptSink) {
        self.state.transcript_sink = Some(sink);
    }

    async fn encrypt(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext: Vec<u8>,
        record: bool,
    ) -> Result<Vec<u8>, StreamCipherError> {
        self.encrypt(explicit_nonce, plaintext, record, false).await
    }

    async fn encrypt_private(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext: Vec<u8>,
        record: bool,
    ) -> Result<Vec<u8>, StreamCipherError> {
        self.encrypt(explicit_nonce, plaintext, record, true).await
    }

    async fn decrypt(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        record: bool,
    ) -> Result<Vec<u8>, StreamCipherError> {
        let len = ciphertext.len();
        let labels = self.build_ctr_labels(ciphertext.len()).await?;

        let (plaintext, _) = self
            .ctr_mode
            .apply_key_stream(
                explicit_nonce.clone(),
                Some(ciphertext.clone()),
                len,
                labels,
                false,
            )
            .await?;

        if record {
            // Receive plaintext labels directly from follower
            let msg = expect_msg_or_err!(
                self.channel.next().await,
                StreamCipherMessage::PlaintextLabels,
                StreamCipherError::UnexpectedMessage
            )?;

            let PlaintextLabels {
                labels: plaintext_labels,
            } = msg;

            if plaintext_labels.len() != plaintext.len() {
                return Err(StreamCipherError::IncorrectLabelCount(
                    plaintext.len(),
                    plaintext_labels.len(),
                ));
            }

            self.write_to_transcript(
                explicit_nonce,
                plaintext.clone(),
                plaintext_labels,
                ciphertext.clone(),
            )
            .await?;
        }

        Ok(plaintext)
    }

    async fn decrypt_private(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        record: bool,
    ) -> Result<Vec<u8>, StreamCipherError> {
        let len = ciphertext.len();
        // Generate a random mask to hide the key stream
        let mut stream_mask = vec![0u8; ciphertext.len()];
        rand::thread_rng().fill_bytes(&mut stream_mask);

        let labels = self.build_ctr_labels(ciphertext.len()).await?;

        let (masked_stream, summaries) = self
            .ctr_mode
            .apply_key_stream(
                explicit_nonce.clone(),
                Some(stream_mask.clone()),
                len,
                labels,
                true,
            )
            .await?;

        // Remove the mask and decrypt ciphertext
        let plaintext = masked_stream
            .into_iter()
            .zip(stream_mask)
            .zip(ciphertext.clone())
            .map(|((masked_stream, mask), ciphertext)| masked_stream ^ mask ^ ciphertext)
            .collect::<Vec<u8>>();

        if record {
            let key_stream_labels = extract_key_stream_labels::<C>(plaintext.len(), summaries);

            let plaintext_labels = self
                .prove_ciphertext(plaintext.clone(), key_stream_labels)
                .await?;

            self.write_to_transcript(
                explicit_nonce,
                plaintext.clone(),
                plaintext_labels,
                ciphertext,
            )
            .await?;
        }

        Ok(plaintext)
    }

    async fn share_key_block(
        &mut self,
        explicit_nonce: Vec<u8>,
        ctr: u32,
    ) -> Result<Vec<u8>, StreamCipherError> {
        let labels = self.build_ctr_share_labels().await?;

        self.ctr_mode
            .share_key_block(explicit_nonce, ctr, labels)
            .await
    }
}

fn extract_plaintext_labels<C: CtrCircuitSuite>(
    len: usize,
    summaries: Vec<DESummary>,
) -> ActiveLabels {
    let cipher = C::CtrCircuit::default();
    let input_text_index = cipher.input_text().index();

    let mut plaintext_labels = Vec::with_capacity(summaries.len() * C::CtrCircuit::BLOCK_SIZE);
    for summary in summaries {
        let input_labels = summary.get_evaluator_summary().input_labels();

        let input_text_labels = input_labels[input_text_index]
            .iter()
            .collect::<Vec<Label>>();

        plaintext_labels.extend(input_text_labels);
    }
    plaintext_labels.truncate(len * 8);

    ActiveLabels::new_active(plaintext_labels)
}

/// Extracts the key stream labels from execution summaries.
fn extract_key_stream_labels<C: CtrCircuitSuite>(
    len: usize,
    summaries: Vec<DESummary>,
) -> ActiveLabels {
    let cipher = C::CtrCircuit::default();
    let input_text_index = cipher.input_text().index();
    let output_text_index = cipher.output_text().index();

    let mut key_stream_labels = Vec::with_capacity(summaries.len() * C::CtrCircuit::BLOCK_SIZE);
    for summary in summaries {
        let input_labels = summary.get_evaluator_summary().input_labels();
        let output_labels = summary.get_evaluator_summary().output_labels();

        let input_text_labels = input_labels[input_text_index].clone().into_labels();
        let output_text_labels = output_labels[output_text_index].clone().into_labels();

        let key_block_labels = (input_text_labels ^ output_text_labels)
            .iter()
            .collect::<Vec<Label>>();

        key_stream_labels.extend(key_block_labels);
    }
    key_stream_labels.truncate(len * 8);

    ActiveLabels::new_active(key_stream_labels)
}
