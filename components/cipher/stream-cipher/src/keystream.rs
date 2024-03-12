use std::{collections::VecDeque, marker::PhantomData};

use mpz_garble::{value::ValueRef, Execute, Load, Memory, Prove, Thread, ThreadPool, Verify};
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

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    pub(crate) async fn preprocess<T>(
        &mut self,
        pool: &mut ThreadPool<T>,
        key: &ValueRef,
        iv: &ValueRef,
        len: usize,
    ) -> Result<(), StreamCipherError>
    where
        T: Thread + Memory + Load + Send + 'static,
    {
        let block_count = (len / C::BLOCK_LEN) + (len % C::BLOCK_LEN != 0) as usize;
        let vars = self.define_vars(pool.get_mut(), block_count)?;

        let mut scope = pool.new_scope();
        for (block, nonce, ctr) in vars.iter() {
            scope.push(move |thread| {
                Box::pin(preprocess_block::<T, C>(
                    thread,
                    key.clone(),
                    iv.clone(),
                    block.clone(),
                    nonce.clone(),
                    ctr.clone(),
                ))
            });
        }
        scope
            .wait()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        self.preprocessed.extend(vars);

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    pub(crate) async fn compute<T>(
        &mut self,
        pool: &mut ThreadPool<T>,
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
        let explicit_nonce: C::NONCE = explicit_nonce.try_into().map_err(|_| {
            StreamCipherError::InvalidExplicitNonceLength {
                expected: C::NONCE_LEN,
                actual: explicit_nonce_len,
            }
        })?;

        // Take any preprocessed blocks if available, and define new ones if needed.
        let vars = if !self.preprocessed.is_empty() {
            let mut vars = self
                .preprocessed
                .drain(block_count.min(self.preprocessed.len()));
            if vars.len() < block_count {
                vars.extend(self.define_vars(pool.get_mut(), block_count - vars.len())?)
            }
            vars
        } else {
            self.define_vars(pool.get_mut(), block_count)?
        };

        let mut scope = pool.new_scope();
        for (i, (block, nonce, ctr)) in vars.iter().enumerate() {
            scope.push(move |thread| {
                Box::pin(compute_block::<T, C>(
                    thread,
                    mode,
                    key.clone(),
                    iv.clone(),
                    block.clone(),
                    nonce.clone(),
                    ctr.clone(),
                    explicit_nonce,
                    (start_ctr + i) as u32,
                ))
            });
        }
        scope
            .wait()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        let keystream = pool.get_mut().array_from_values(&vars.flatten(len))?;

        Ok(keystream)
    }
}

async fn preprocess_block<T, C>(
    thread: &mut T,
    key: ValueRef,
    iv: ValueRef,
    block: ValueRef,
    nonce: ValueRef,
    ctr: ValueRef,
) -> Result<(), StreamCipherError>
where
    T: Load + Send,
    C: CtrCircuit,
{
    thread
        .load(
            C::circuit(),
            &[key.clone(), iv.clone(), nonce.clone(), ctr.clone()],
            &[block.clone()],
        )
        .await
        .map_err(StreamCipherError::from)
}

async fn compute_block<T, C>(
    thread: &mut T,
    mode: ExecutionMode,
    key: ValueRef,
    iv: ValueRef,
    block: ValueRef,
    nonce_ref: ValueRef,
    ctr_ref: ValueRef,
    nonce: C::NONCE,
    ctr: u32,
) -> Result<(), StreamCipherError>
where
    T: Memory + Execute + Prove + Verify + Send,
    C: CtrCircuit,
{
    thread.assign(&nonce_ref, nonce)?;
    thread.assign(&ctr_ref, ctr.to_be_bytes())?;

    match mode {
        ExecutionMode::Mpc => {
            thread
                .execute(C::circuit(), &[key, iv, nonce_ref, ctr_ref], &[block])
                .await?;
        }
        ExecutionMode::Prove => {
            thread
                .execute_prove(C::circuit(), &[key, iv, nonce_ref, ctr_ref], &[block])
                .await?;
        }
        ExecutionMode::Verify => {
            thread
                .execute_verify(C::circuit(), &[key, iv, nonce_ref, ctr_ref], &[block])
                .await?;
        }
    }

    Ok(())
}
