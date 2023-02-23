use std::{marker::PhantomData, sync::Arc};

use futures::StreamExt;
use tokio::sync::Semaphore;

use crate::{
    cipher::{CtrCircuit, CtrCircuitSuite, CtrShareCircuit},
    config::CounterModeConfig,
    counter_block::{apply_key_block, share_key_block, KeyBlockLabels},
    utils::block_count,
    StreamCipherError,
};
use mpc_aio::protocol::garble::{exec::dual::DEExecute, factory::GCFactoryError};
use mpc_core::garble::exec::dual::{DESummary, DualExConfig, DualExConfigBuilder};
use utils_aio::factory::AsyncFactory;

pub struct CtrMode<C, DEF, DE>
where
    C: CtrCircuitSuite,
    DEF: AsyncFactory<DE, Config = DualExConfig, Error = GCFactoryError> + Clone,
    DE: DEExecute,
{
    config: CounterModeConfig,

    execution_id: usize,

    de_factory: DEF,

    _cipher: PhantomData<C>,
    _de: PhantomData<DE>,
}

impl<C, DEF, DE> CtrMode<C, DEF, DE>
where
    C: CtrCircuitSuite,
    DEF: AsyncFactory<DE, Config = DualExConfig, Error = GCFactoryError> + Clone,
    DE: DEExecute,
{
    pub fn new(config: CounterModeConfig, de_factory: DEF) -> Self {
        Self {
            config,
            execution_id: 0,
            de_factory,
            _cipher: PhantomData,
            _de: PhantomData,
        }
    }

    fn get_full_execution_id(&self, ctr: usize) -> String {
        // Instance ID / Execution ID / Counter
        format!("{}/{}/{ctr}", self.config.id, self.execution_id)
    }

    pub async fn share_key_block(
        &mut self,
        explicit_nonce: Vec<u8>,
        ctr: u32,
        labels: KeyBlockLabels,
    ) -> Result<Vec<u8>, StreamCipherError> {
        let id = self.get_full_execution_id(ctr as usize);
        self.execution_id += 1;

        let de_config = DualExConfigBuilder::default()
            .id(id.clone())
            .circ(C::CtrShareCircuit::default().circuit())
            .build()
            .expect("DualExConfig should be valid");

        let de = self.de_factory.create(id, de_config).await?;

        let share = share_key_block::<C::CtrShareCircuit, DE>(
            self.config.role,
            de,
            labels,
            explicit_nonce,
            ctr,
        )
        .await?;

        Ok(share)
    }

    pub async fn apply_key_stream(
        &mut self,
        explicit_nonce: Vec<u8>,
        mut text: Option<Vec<u8>>,
        len: usize,
        labels: Vec<KeyBlockLabels>,
        private: bool,
    ) -> Result<(Vec<u8>, Vec<DESummary>), StreamCipherError> {
        let block_count = block_count(len, C::BLOCK_SIZE);
        let padded_length = block_count * C::BLOCK_SIZE;

        if let Some(text) = text.as_mut() {
            debug_assert!(text.len() == len);
            // Pad text to a multiple of block size
            text.resize(padded_length, 0);
        }

        let semaphore = Arc::new(Semaphore::new(self.config.concurrency));
        let mut futs = (0..block_count)
            .zip(labels)
            .map(|(block_number, block_labels)| {
                let ctr = block_number + self.config.start_ctr;

                let explicit_nonce = explicit_nonce.clone();
                let text = if let Some(text) = text.as_mut() {
                    Some(text.drain(..C::BLOCK_SIZE).collect())
                } else {
                    None
                };

                let id = self.get_full_execution_id(ctr);

                let de_config = DualExConfigBuilder::default()
                    .id(id.clone())
                    .circ(C::CtrCircuit::default().circuit())
                    .build()
                    .expect("DualExConfig should be valid");

                let mut de_factory = self.de_factory.clone();

                let semaphore = semaphore.clone();
                async move {
                    let permit = semaphore
                        .acquire()
                        .await
                        .expect("Semaphore should not be dropped");

                    let de = de_factory.create(id, de_config).await?;

                    let (output_text, summary) = apply_key_block::<C::CtrCircuit, DE>(
                        de,
                        block_labels,
                        text,
                        explicit_nonce,
                        ctr as u32,
                        private,
                    )
                    .await?;

                    drop(permit);

                    Result::<_, StreamCipherError>::Ok((output_text, summary))
                }
            })
            .collect::<futures::stream::FuturesOrdered<_>>();

        let mut msg = Vec::with_capacity(padded_length);
        let mut summaries = Vec::with_capacity(block_count);
        while let Some(result) = futs.next().await {
            let (block_text, block_summary) = result?;

            msg.extend(block_text);
            summaries.push(block_summary);
        }

        // Strip any padding
        msg.truncate(len);

        self.execution_id += 1;

        Ok((msg, summaries))
    }
}
