use std::{collections::VecDeque, marker::PhantomData};

use mpz_garble::{value::ValueRef, Execute, Load, Memory, Prove, Thread, Verify};
use tracing::instrument;
use utils::id::NestedId;

use crate::{config::ExecutionMode, CtrCircuit, StreamCipherError};

pub(crate) struct KeyStream<C> {
    block_counter: NestedId,
    preprocessed: BlockVars,
    _pd: PhantomData<C>,
}

#[derive(Default)]
struct BlockVars {
    blocks: VecDeque<ValueRef>,
    nonces: VecDeque<ValueRef>,
    ctrs: VecDeque<ValueRef>,
}

impl BlockVars {
    fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    fn len(&self) -> usize {
        self.blocks.len()
    }

    fn drain(&mut self, count: usize) -> BlockVars {
        let blocks = self.blocks.drain(0..count).collect();
        let nonces = self.nonces.drain(0..count).collect();
        let ctrs = self.ctrs.drain(0..count).collect();

        BlockVars {
            blocks,
            nonces,
            ctrs,
        }
    }

    fn extend(&mut self, vars: BlockVars) {
        self.blocks.extend(vars.blocks);
        self.nonces.extend(vars.nonces);
        self.ctrs.extend(vars.ctrs);
    }

    fn iter(&self) -> impl Iterator<Item = (&ValueRef, &ValueRef, &ValueRef)> {
        self.blocks
            .iter()
            .zip(self.nonces.iter())
            .zip(self.ctrs.iter())
            .map(|((block, nonce), ctr)| (block, nonce, ctr))
    }

    fn flatten(&self, len: usize) -> Vec<ValueRef> {
        self.blocks
            .iter()
            .flat_map(|block| block.iter())
            .cloned()
            .take(len)
            .map(|byte| ValueRef::Value { id: byte })
            .collect()
    }
}

impl<C: CtrCircuit> KeyStream<C> {
    pub(crate) fn new(id: &str) -> Self {
        let block_counter = NestedId::new(id).append_counter();
        Self {
            block_counter,
            preprocessed: BlockVars::default(),
            _pd: PhantomData,
        }
    }

    fn define_vars(
        &mut self,
        mem: &mut impl Memory,
        count: usize,
    ) -> Result<BlockVars, StreamCipherError> {
        let mut vars = BlockVars::default();
        for _ in 0..count {
            let block_id = self.block_counter.increment_in_place();
            let block = mem.new_output::<C::BLOCK>(&block_id.to_string())?;
            let nonce =
                mem.new_public_input::<C::NONCE>(&block_id.append_string("nonce").to_string())?;
            let ctr =
                mem.new_public_input::<[u8; 4]>(&block_id.append_string("ctr").to_string())?;

            vars.blocks.push_back(block);
            vars.nonces.push_back(nonce);
            vars.ctrs.push_back(ctr);
        }

        Ok(vars)
    }

    #[instrument(level = "debug", skip_all, err)]
    pub(crate) async fn preprocess<T>(
        &mut self,
        thread: &mut T,
        key: &ValueRef,
        iv: &ValueRef,
        len: usize,
    ) -> Result<(), StreamCipherError>
    where
        T: Thread + Memory + Load + Send + 'static,
    {
        let block_count = (len / C::BLOCK_LEN) + (len % C::BLOCK_LEN != 0) as usize;
        let vars = self.define_vars(thread, block_count)?;

        let calls = vars
            .iter()
            .map(|(block, nonce, ctr)| {
                (
                    C::circuit(),
                    vec![key.clone(), iv.clone(), nonce.clone(), ctr.clone()],
                    vec![block.clone()],
                )
            })
            .collect::<Vec<_>>();

        for (circ, inputs, outputs) in calls {
            thread.load(circ, &inputs, &outputs).await?;
        }

        self.preprocessed.extend(vars);

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    pub(crate) async fn compute<T>(
        &mut self,
        thread: &mut T,
        mode: ExecutionMode,
        key: &ValueRef,
        iv: &ValueRef,
        explicit_nonce: Vec<u8>,
        start_ctr: usize,
        len: usize,
    ) -> Result<ValueRef, StreamCipherError>
    where
        T: Thread + Memory + Execute + Prove + Verify + Send + 'static,
    {
        let block_count = (len / C::BLOCK_LEN) + (len % C::BLOCK_LEN != 0) as usize;
        let explicit_nonce_len = explicit_nonce.len();
        let explicit_nonce: C::NONCE = explicit_nonce
            .try_into()
            .map_err(|_| StreamCipherError::explicit_nonce_len::<C>(explicit_nonce_len))?;

        // Take any preprocessed blocks if available, and define new ones if needed.
        let vars = if !self.preprocessed.is_empty() {
            let mut vars = self
                .preprocessed
                .drain(block_count.min(self.preprocessed.len()));
            if vars.len() < block_count {
                vars.extend(self.define_vars(thread, block_count - vars.len())?)
            }
            vars
        } else {
            self.define_vars(thread, block_count)?
        };

        let mut calls = Vec::with_capacity(vars.len());
        let mut inputs = Vec::with_capacity(vars.len() * 4);
        for (i, (block, nonce_ref, ctr_ref)) in vars.iter().enumerate() {
            thread.assign(nonce_ref, explicit_nonce)?;
            thread.assign(ctr_ref, ((start_ctr + i) as u32).to_be_bytes())?;

            inputs.push(key.clone());
            inputs.push(iv.clone());
            inputs.push(nonce_ref.clone());
            inputs.push(ctr_ref.clone());

            calls.push((
                C::circuit(),
                vec![key.clone(), iv.clone(), nonce_ref.clone(), ctr_ref.clone()],
                vec![block.clone()],
            ));
        }

        match mode {
            ExecutionMode::Mpc => {
                thread.commit(&inputs).await?;
                for (circ, inputs, outputs) in calls {
                    thread.execute(circ, &inputs, &outputs).await?;
                }
            }
            ExecutionMode::Prove => {
                // Note that after the circuit execution, the value of `block` can be considered as
                // implicitly authenticated since `key` and `iv` have already been authenticated earlier
                // and `nonce_ref` and `ctr_ref` are public.
                // [Prove::prove] will **not** be called on `block` at any later point.
                thread.commit_prove(&inputs).await?;
                for (circ, inputs, outputs) in calls {
                    thread.execute_prove(circ, &inputs, &outputs).await?;
                }
            }
            ExecutionMode::Verify => {
                thread.commit_verify(&inputs).await?;
                for (circ, inputs, outputs) in calls {
                    thread.execute_verify(circ, &inputs, &outputs).await?;
                }
            }
        }

        let keystream = thread.array_from_values(&vars.flatten(len))?;

        Ok(keystream)
    }
}
