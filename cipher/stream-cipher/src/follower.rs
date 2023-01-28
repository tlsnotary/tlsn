use std::{marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use futures::{channel::mpsc::Sender, lock::Mutex, SinkExt, StreamExt};
use tokio::sync::Semaphore;

use crate::{
    cipher::{CtrCircuit, CtrCircuitSuite, CtrShareCircuit},
    config::StreamCipherFollowerConfig,
    counter_block::{follower_apply_key_block, follower_share_key_block},
    BlindMessageTranscript, StreamCipherError, StreamCipherFollower, StreamCipherLabels,
};
use mpc_aio::protocol::garble::{
    exec::{
        deap::{DEAPExecute, DEAPVerify},
        dual::DEExecute,
    },
    factory::GCFactoryError,
};
use mpc_core::garble::{
    exec::{
        deap::{DEAPConfig, DEAPConfigBuilder},
        dual::{DualExConfig, DualExConfigBuilder},
    },
    ActiveEncodedInput, ChaChaEncoder, Encoder, FullEncodedInput, FullInputSet,
};
use utils_aio::factory::AsyncFactory;

#[derive(Default)]
pub struct State {
    pub(super) execution_id: usize,
    pub(super) encoder: Option<Arc<Mutex<ChaChaEncoder>>>,
    pub(super) labels: Option<StreamCipherLabels>,
    pub(super) pending: Vec<Box<dyn DEAPVerify>>,
    pub(super) transcript_sink: Option<Sender<BlindMessageTranscript>>,
}

pub struct DEAPStreamCipherFollower<C, DPF, DEF, DP, DE>
where
    C: CtrCircuitSuite,
    DPF: AsyncFactory<DP, Config = DEAPConfig, Error = GCFactoryError> + Clone + Send,
    DEF: AsyncFactory<DE, Config = DualExConfig, Error = GCFactoryError> + Clone + Send,
    DP: DEAPExecute,
    DE: DEExecute,
{
    config: StreamCipherFollowerConfig,
    state: State,

    deap_factory: DPF,
    de_factory: DEF,

    _cipher: PhantomData<C>,
    _deap: PhantomData<DP>,
    _de: PhantomData<DE>,
}

impl<C, DPF, DEF, DP, DE> DEAPStreamCipherFollower<C, DPF, DEF, DP, DE>
where
    C: CtrCircuitSuite,
    DPF: AsyncFactory<DP, Config = DEAPConfig, Error = GCFactoryError> + Clone + Send,
    DEF: AsyncFactory<DE, Config = DualExConfig, Error = GCFactoryError> + Clone + Send,
    DP: DEAPExecute,
    DE: DEExecute,
{
    /// Create a new stream cipher follower
    ///
    /// * `config` - The configuration for the follower
    /// * `mux_control` - Multiplexer control to establish channels with the leader
    /// * `backend` - The backend to use for garbled circuit computations
    /// * `ot_sender_factory` - Factory to create OT senders
    pub fn new(
        config: StreamCipherFollowerConfig,
        deap_factory: DPF,
        de_factory: DEF,
    ) -> DEAPStreamCipherFollower<C, DPF, DEF, DP, DE> {
        DEAPStreamCipherFollower {
            config,
            state: State::default(),
            deap_factory,
            de_factory,
            _cipher: PhantomData,
            _deap: PhantomData,
            _de: PhantomData,
        }
    }
}

#[async_trait]
impl<C, DPF, DEF, DP, DE> StreamCipherFollower<C> for DEAPStreamCipherFollower<C, DPF, DEF, DP, DE>
where
    C: CtrCircuitSuite,
    DPF: AsyncFactory<DP, Config = DEAPConfig, Error = GCFactoryError> + Clone + Send,
    DEF: AsyncFactory<DE, Config = DualExConfig, Error = GCFactoryError> + Clone + Send,
    DP: DEAPExecute,
    DE: DEExecute,
{
    fn set_keys(&mut self, labels: StreamCipherLabels) {
        self.state.labels = Some(labels);
    }

    fn set_encoder(&mut self, encoder: Arc<Mutex<ChaChaEncoder>>) {
        self.state.encoder = Some(encoder);
    }

    fn set_transcript_sink(&mut self, sink: Sender<BlindMessageTranscript>) {
        self.state.transcript_sink = Some(sink);
    }

    async fn apply_key_stream(
        &mut self,
        explicit_nonce: Vec<u8>,
        msg_len: usize,
        record: bool,
    ) -> Result<Vec<u8>, StreamCipherError> {
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

        let block_size = C::BLOCK_SIZE;

        // Divide msg length by block size rounding up
        let block_count = (msg_len / block_size) + (msg_len % block_size != 0) as usize;
        let start_ctr = self.config.start_ctr;
        let end_ctr = start_ctr + block_count;

        // Instance ID / Execution ID
        let id = format!("{}/{}", self.config.id, self.state.execution_id);
        self.state.execution_id += 1;

        let semaphore = Arc::new(Semaphore::new(self.config.concurrency));
        let mut futs = (start_ctr..end_ctr)
            .map(|ctr| {
                // Instance ID / Execution ID / Counter
                let id = format!("{}/{}", id.clone(), ctr);

                let semaphore = semaphore.clone();

                let len = if ctr < end_ctr - 1 {
                    block_size
                } else {
                    // If last block, length is the remainder of the message length
                    let remainder = msg_len % block_size;
                    if remainder == 0 {
                        block_size
                    } else {
                        remainder
                    }
                };

                let deap_config = DEAPConfigBuilder::default()
                    .id(id.clone())
                    .circ(C::CtrCircuit::default().circuit())
                    .build()
                    .expect("DEAPConfigBuilder should be valid");

                let mut deap_factory = self.deap_factory.clone();
                let encoder = encoder.clone();
                let encoder_default_stream_id = self.config.encoder_default_stream_id;
                let encoder_text_stream_id = self.config.encoder_text_stream_id;
                let cipher_labels = cipher_labels.clone();
                let explicit_nonce = explicit_nonce.clone();

                async move {
                    let permit = semaphore
                        .acquire()
                        .await
                        .expect("Semaphore should not be dropped");

                    let deap = deap_factory.create(id, deap_config).await?;

                    let (gen_labels, cached_labels) = build_ctr_labels::<C::CtrCircuit>(
                        encoder,
                        encoder_default_stream_id,
                        encoder_text_stream_id,
                        cipher_labels.clone(),
                        len,
                        record,
                    )
                    .await;

                    let (block_transcript, follower) =
                        follower_apply_key_block::<C::CtrCircuit, DP>(
                            deap,
                            gen_labels,
                            cached_labels,
                            len,
                            explicit_nonce,
                            ctr as u32,
                        )
                        .await?;

                    drop(permit);

                    Result::<_, StreamCipherError>::Ok((block_transcript, follower))
                }
            })
            .collect::<futures::stream::FuturesOrdered<_>>();

        let mut transcript = BlindMessageTranscript::new(explicit_nonce);
        let mut msg = Vec::with_capacity(block_count * block_size);
        while let Some(result) = futs.next().await {
            let (block_transcript, follower) = result?;

            msg.extend_from_slice(block_transcript.get_output_text());
            transcript.append(block_transcript);
            self.state.pending.push(follower);
        }

        // Push transcript into sink if configured
        if record {
            if let Some(ref mut sink) = self.state.transcript_sink {
                sink.send(transcript).await?;
            }
        }

        Ok(msg)
    }

    async fn share_key_block(
        &mut self,
        explicit_nonce: Vec<u8>,
        ctr: u32,
        mask: Vec<u8>,
    ) -> Result<Vec<u8>, StreamCipherError> {
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

        // Instance ID / Execution ID
        let id = format!("{}/{}", self.config.id, self.state.execution_id);
        self.state.execution_id += 1;

        let de_config = DualExConfigBuilder::default()
            .id(id.clone())
            .circ(C::CtrShareCircuit::default().circuit())
            .build()
            .expect("DualExConfig should be valid");
        let de = self.de_factory.create(id, de_config).await?;

        let (gen_labels, cached_labels) = build_ctr_share_labels::<C::CtrShareCircuit>(
            encoder,
            self.config.encoder_default_stream_id,
            cipher_labels,
        )
        .await;

        let share = follower_share_key_block::<C::CtrShareCircuit, DE>(
            de,
            gen_labels,
            cached_labels,
            mask,
            explicit_nonce,
            ctr,
        )
        .await?;

        Ok(share)
    }

    async fn verify_key_stream(
        &mut self,
        _nonce: Vec<u8>,
        _msg_out: Vec<u8>,
        _record: bool,
    ) -> Result<(), StreamCipherError> {
        todo!()
    }

    async fn finalize(self) -> Result<(), StreamCipherError> {
        let semaphore = Arc::new(Semaphore::new(self.config.concurrency));
        let mut futs = self
            .state
            .pending
            .into_iter()
            .map(|follower| {
                let semaphore = semaphore.clone();

                async move {
                    let permit = semaphore
                        .acquire()
                        .await
                        .expect("Semaphore should not be dropped");

                    follower.verify_boxed().await?;

                    drop(permit);

                    Result::<_, StreamCipherError>::Ok(())
                }
            })
            .collect::<futures::stream::FuturesOrdered<_>>();

        while let Some(verify_fut) = futs.next().await {
            verify_fut?;
        }

        Ok(())
    }
}

async fn build_ctr_labels<C: CtrCircuit>(
    encoder: Arc<Mutex<ChaChaEncoder>>,
    encoder_default_stream_id: u32,
    encoder_text_stream_id: u32,
    labels: StreamCipherLabels,
    len: usize,
    record: bool,
) -> (FullInputSet, Vec<ActiveEncodedInput>) {
    let cipher = C::default();

    let key_labels = FullEncodedInput::from_labels(cipher.key(), labels.key_full)
        .expect("Key labels should be valid");
    let iv_labels = FullEncodedInput::from_labels(cipher.iv(), labels.iv_full)
        .expect("IV labels should be valid");

    let mut encoder = encoder.lock().await;
    let padding = C::BLOCK_SIZE - len;
    let block_labels = if record {
        encoder.encode_padded(
            encoder_text_stream_id,
            &cipher.text(),
            padding,
            C::IS_REVERSED,
        )
    } else {
        encoder.encode(encoder_default_stream_id, &cipher.text(), false)
    };
    let nonce_labels = encoder.encode(encoder_default_stream_id, &cipher.nonce(), false);
    let ctr_labels = encoder.encode(encoder_default_stream_id, &cipher.counter(), false);
    drop(encoder);

    let gen_labels = FullInputSet::new(vec![
        key_labels,
        iv_labels,
        block_labels,
        nonce_labels,
        ctr_labels,
    ])
    .expect("Label set should be valid");

    let cached_labels = vec![
        ActiveEncodedInput::from_active_labels(cipher.key(), labels.key_active)
            .expect("Key labels should be valid"),
        ActiveEncodedInput::from_active_labels(cipher.iv(), labels.iv_active)
            .expect("IV labels should be valid"),
    ];

    (gen_labels, cached_labels)
}

async fn build_ctr_share_labels<C: CtrShareCircuit>(
    encoder: Arc<Mutex<ChaChaEncoder>>,
    encoder_stream_id: u32,
    labels: StreamCipherLabels,
) -> (FullInputSet, Vec<ActiveEncodedInput>) {
    let cipher = C::default();

    let full_key_labels = FullEncodedInput::from_labels(cipher.key(), labels.key_full)
        .expect("Key labels should be valid");
    let full_iv_labels = FullEncodedInput::from_labels(cipher.iv(), labels.iv_full)
        .expect("IV labels should be valid");

    let mut encoder = encoder.lock().await;
    let nonce_labels = encoder.encode(encoder_stream_id, &cipher.nonce(), false);
    let ctr_labels = encoder.encode(encoder_stream_id, &cipher.counter(), false);
    let mask_0_labels = encoder.encode(encoder_stream_id, &cipher.mask_0(), false);
    let mask_1_labels = encoder.encode(encoder_stream_id, &cipher.mask_1(), false);
    drop(encoder);

    let gen_labels = FullInputSet::new(vec![
        full_key_labels,
        full_iv_labels,
        nonce_labels,
        ctr_labels,
        mask_0_labels,
        mask_1_labels,
    ])
    .expect("Label set should be valid");

    let cached_labels = vec![
        ActiveEncodedInput::from_active_labels(cipher.key(), labels.key_active)
            .expect("Key labels should be valid"),
        ActiveEncodedInput::from_active_labels(cipher.iv(), labels.iv_active)
            .expect("IV labels should be valid"),
    ];

    (gen_labels, cached_labels)
}
