use async_trait::async_trait;
use mpz_circuits::types::Value;
use std::{collections::HashMap, fmt::Debug, marker::PhantomData};

use mpz_garble::{
    value::ValueRef, Decode, DecodePrivate, Execute, Memory, Prove, Thread, ThreadPool, Verify,
};
use utils::id::NestedId;

use crate::{
    cipher::CtrCircuit,
    circuit::build_array_xor,
    config::{InputText, KeyBlockConfig, StreamCipherConfig},
    StreamCipher, StreamCipherError,
};

/// An MPC stream cipher.
pub struct MpcStreamCipher<C, E>
where
    C: CtrCircuit,
    E: Thread + Execute + Decode + DecodePrivate + Send + Sync,
{
    config: StreamCipherConfig,
    state: State,
    thread_pool: ThreadPool<E>,

    _cipher: PhantomData<C>,
}

struct State {
    /// Encoded key and IV for the cipher.
    encoded_key_iv: Option<EncodedKeyAndIv>,
    /// Key and IV for the cipher.
    key_iv: Option<KeyAndIv>,
    /// Unique identifier for each execution of the cipher.
    execution_id: NestedId,
    /// Unique identifier for each byte in the transcript.
    transcript_counter: NestedId,
    /// Unique identifier for each byte in the ciphertext (prefixed with execution id).
    ciphertext_counter: NestedId,
    /// Persists the transcript counter for each transcript id.
    transcript_state: HashMap<String, NestedId>,
}

#[derive(Clone)]
struct EncodedKeyAndIv {
    key: ValueRef,
    iv: ValueRef,
}

#[derive(Clone)]
struct KeyAndIv {
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl<C, E> MpcStreamCipher<C, E>
where
    C: CtrCircuit,
    E: Thread + Execute + Prove + Verify + Decode + DecodePrivate + Send + Sync + 'static,
{
    /// Creates a new counter-mode cipher.
    pub fn new(config: StreamCipherConfig, thread_pool: ThreadPool<E>) -> Self {
        let execution_id = NestedId::new(&config.id).append_counter();
        let transcript_counter = NestedId::new(&config.transcript_id).append_counter();
        let ciphertext_counter = execution_id.append_string("ciphertext").append_counter();

        Self {
            config,
            state: State {
                encoded_key_iv: None,
                key_iv: None,
                execution_id,
                transcript_counter,
                ciphertext_counter,
                transcript_state: HashMap::new(),
            },
            thread_pool,
            _cipher: PhantomData,
        }
    }

    /// Returns unique identifiers for the next bytes in the transcript.
    fn plaintext_ids(&mut self, len: usize) -> Vec<String> {
        (0..len)
            .map(|_| {
                self.state
                    .transcript_counter
                    .increment_in_place()
                    .to_string()
            })
            .collect()
    }

    /// Returns unique identifiers for the next bytes in the ciphertext.
    fn ciphertext_ids(&mut self, len: usize) -> Vec<String> {
        (0..len)
            .map(|_| {
                self.state
                    .ciphertext_counter
                    .increment_in_place()
                    .to_string()
            })
            .collect()
    }

    async fn compute_keystream(
        &mut self,
        explicit_nonce: Vec<u8>,
        start_ctr: usize,
        len: usize,
        mode: ExecutionMode,
    ) -> Result<ValueRef, StreamCipherError> {
        let EncodedKeyAndIv { key, iv } = self
            .state
            .encoded_key_iv
            .clone()
            .ok_or(StreamCipherError::KeyIvNotSet)?;

        let explicit_nonce_len = explicit_nonce.len();
        let explicit_nonce: C::NONCE = explicit_nonce.try_into().map_err(|_| {
            StreamCipherError::InvalidExplicitNonceLength {
                expected: C::NONCE_LEN,
                actual: explicit_nonce_len,
            }
        })?;

        // Divide msg length by block size rounding up
        let block_count = (len / C::BLOCK_LEN) + (len % C::BLOCK_LEN != 0) as usize;

        let block_configs = (0..block_count)
            .map(|i| {
                KeyBlockConfig::<C>::new(
                    key.clone(),
                    iv.clone(),
                    explicit_nonce,
                    (start_ctr + i) as u32,
                )
            })
            .collect::<Vec<_>>();

        let execution_id = self.state.execution_id.increment_in_place();

        let keystream = compute_keystream(
            &mut self.thread_pool,
            execution_id,
            block_configs,
            len,
            mode,
        )
        .await?;

        Ok(keystream)
    }

    /// Applies the keystream to the provided input text.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip(self), err)
    )]
    async fn apply_keystream(
        &mut self,
        input_text: InputText,
        keystream: ValueRef,
        mode: ExecutionMode,
    ) -> Result<ValueRef, StreamCipherError> {
        let execution_id = self.state.execution_id.increment_in_place();

        let mut scope = self.thread_pool.new_scope();
        scope.push(move |thread| {
            Box::pin(apply_keystream(
                thread,
                mode,
                execution_id,
                input_text,
                keystream,
            ))
        });

        let output_text = scope.wait().await.into_iter().next().unwrap()?;

        Ok(output_text)
    }

    async fn decode_public(&mut self, value: ValueRef) -> Result<Value, StreamCipherError> {
        let mut scope = self.thread_pool.new_scope();
        scope.push(move |thread| Box::pin(async move { thread.decode(&[value]).await }));
        let mut output = scope.wait().await.into_iter().next().unwrap()?;
        Ok(output.pop().unwrap())
    }

    async fn decode_private(&mut self, value: ValueRef) -> Result<Value, StreamCipherError> {
        let mut scope = self.thread_pool.new_scope();
        scope.push(move |thread| Box::pin(async move { thread.decode_private(&[value]).await }));
        let mut output = scope.wait().await.into_iter().next().unwrap()?;
        Ok(output.pop().unwrap())
    }

    async fn decode_blind(&mut self, value: ValueRef) -> Result<(), StreamCipherError> {
        let mut scope = self.thread_pool.new_scope();
        scope.push(move |thread| Box::pin(async move { thread.decode_blind(&[value]).await }));
        scope.wait().await.into_iter().next().unwrap()?;
        Ok(())
    }

    async fn prove(&mut self, value: ValueRef) -> Result<(), StreamCipherError> {
        let mut scope = self.thread_pool.new_scope();
        scope.push(move |thread| Box::pin(async move { thread.prove(&[value]).await }));
        scope.wait().await.into_iter().next().unwrap()?;
        Ok(())
    }

    async fn verify(&mut self, value: ValueRef, expected: Value) -> Result<(), StreamCipherError> {
        let mut scope = self.thread_pool.new_scope();
        scope.push(move |thread| {
            Box::pin(async move { thread.verify(&[value], &[expected]).await })
        });
        scope.wait().await.into_iter().next().unwrap()?;
        Ok(())
    }
}

#[async_trait]
impl<C, E> StreamCipher<C> for MpcStreamCipher<C, E>
where
    C: CtrCircuit,
    E: Thread + Execute + Prove + Verify + Decode + DecodePrivate + Send + Sync + 'static,
{
    fn set_key(&mut self, key: ValueRef, iv: ValueRef) {
        self.state.encoded_key_iv = Some(EncodedKeyAndIv { key, iv });
    }

    async fn decode_key_private(&mut self) -> Result<(), StreamCipherError> {
        let EncodedKeyAndIv { key, iv } = self
            .state
            .encoded_key_iv
            .clone()
            .ok_or(StreamCipherError::KeyIvNotSet)?;

        let mut scope = self.thread_pool.new_scope();
        scope.push(move |thread| Box::pin(async move { thread.decode_private(&[key, iv]).await }));
        let output = scope.wait().await.into_iter().next().unwrap()?;

        let [key, iv]: [_; 2] = output.try_into().expect("decoded 2 values");
        let key: Vec<u8> = key.try_into().expect("key is an array");
        let iv: Vec<u8> = iv.try_into().expect("iv is an array");

        self.state.key_iv = Some(KeyAndIv { key, iv });

        Ok(())
    }

    async fn decode_key_blind(&mut self) -> Result<(), StreamCipherError> {
        let EncodedKeyAndIv { key, iv } = self
            .state
            .encoded_key_iv
            .clone()
            .ok_or(StreamCipherError::KeyIvNotSet)?;

        let mut scope = self.thread_pool.new_scope();
        scope.push(move |thread| Box::pin(async move { thread.decode_blind(&[key, iv]).await }));
        scope.wait().await.into_iter().next().unwrap()?;

        Ok(())
    }

    fn set_transcript_id(&mut self, id: &str) {
        let current_id = self
            .state
            .transcript_counter
            .root()
            .expect("root id is set");
        let current_counter = self.state.transcript_counter.clone();
        self.state
            .transcript_state
            .insert(current_id.to_string(), current_counter);

        if let Some(counter) = self.state.transcript_state.get(id) {
            self.state.transcript_counter = counter.clone();
        } else {
            self.state.transcript_counter = NestedId::new(id).append_counter();
        }
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "debug", skip(self, plaintext), err)
    )]
    async fn encrypt_public(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, StreamCipherError> {
        let keystream = self
            .compute_keystream(
                explicit_nonce,
                self.config.start_ctr,
                plaintext.len(),
                ExecutionMode::Mpc,
            )
            .await?;

        let plaintext_ids = self.plaintext_ids(plaintext.len());
        let ciphertext = self
            .apply_keystream(
                InputText::Public {
                    ids: plaintext_ids,
                    text: plaintext,
                },
                keystream,
                ExecutionMode::Mpc,
            )
            .await?;

        let ciphertext: Vec<u8> = self
            .decode_public(ciphertext)
            .await?
            .try_into()
            .expect("ciphertext is array");

        Ok(ciphertext)
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "debug", skip(self, plaintext), err)
    )]
    async fn encrypt_private(
        &mut self,
        explicit_nonce: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, StreamCipherError> {
        let keystream = self
            .compute_keystream(
                explicit_nonce,
                self.config.start_ctr,
                plaintext.len(),
                ExecutionMode::Mpc,
            )
            .await?;

        let plaintext_ids = self.plaintext_ids(plaintext.len());
        let ciphertext = self
            .apply_keystream(
                InputText::Private {
                    ids: plaintext_ids,
                    text: plaintext,
                },
                keystream,
                ExecutionMode::Mpc,
            )
            .await?;

        let ciphertext: Vec<u8> = self
            .decode_public(ciphertext)
            .await?
            .try_into()
            .expect("ciphertext is array");

        Ok(ciphertext)
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "debug", skip(self), err)
    )]
    async fn encrypt_blind(
        &mut self,
        explicit_nonce: Vec<u8>,
        len: usize,
    ) -> Result<Vec<u8>, StreamCipherError> {
        let keystream = self
            .compute_keystream(
                explicit_nonce,
                self.config.start_ctr,
                len,
                ExecutionMode::Mpc,
            )
            .await?;

        let plaintext_ids = self.plaintext_ids(len);
        let ciphertext = self
            .apply_keystream(
                InputText::Blind { ids: plaintext_ids },
                keystream,
                ExecutionMode::Mpc,
            )
            .await?;

        let ciphertext: Vec<u8> = self
            .decode_public(ciphertext)
            .await?
            .try_into()
            .expect("ciphertext is array");

        Ok(ciphertext)
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "debug", skip(self), err)
    )]
    async fn decrypt_public(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, StreamCipherError> {
        // TODO: We may want to support writing to the transcript when decrypting
        // in public mode.
        let keystream = self
            .compute_keystream(
                explicit_nonce,
                self.config.start_ctr,
                ciphertext.len(),
                ExecutionMode::Mpc,
            )
            .await?;

        let ciphertext_ids = self.ciphertext_ids(ciphertext.len());
        let plaintext = self
            .apply_keystream(
                InputText::Public {
                    ids: ciphertext_ids,
                    text: ciphertext,
                },
                keystream,
                ExecutionMode::Mpc,
            )
            .await?;

        let plaintext: Vec<u8> = self
            .decode_public(plaintext)
            .await?
            .try_into()
            .expect("plaintext is array");

        Ok(plaintext)
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "debug", skip(self), err)
    )]
    async fn decrypt_private(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, StreamCipherError> {
        let keystream_ref = self
            .compute_keystream(
                explicit_nonce,
                self.config.start_ctr,
                ciphertext.len(),
                ExecutionMode::Mpc,
            )
            .await?;

        let keystream: Vec<u8> = self
            .decode_private(keystream_ref.clone())
            .await?
            .try_into()
            .expect("keystream is array");

        let plaintext = ciphertext
            .into_iter()
            .zip(keystream)
            .map(|(c, k)| c ^ k)
            .collect::<Vec<_>>();

        // Prove plaintext encrypts back to ciphertext
        let plaintext_ids = self.plaintext_ids(plaintext.len());
        let ciphertext = self
            .apply_keystream(
                InputText::Private {
                    ids: plaintext_ids,
                    text: plaintext.clone(),
                },
                keystream_ref,
                ExecutionMode::Prove,
            )
            .await?;

        self.prove(ciphertext).await?;

        Ok(plaintext)
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "debug", skip(self), err)
    )]
    async fn decrypt_blind(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<(), StreamCipherError> {
        let keystream_ref = self
            .compute_keystream(
                explicit_nonce,
                self.config.start_ctr,
                ciphertext.len(),
                ExecutionMode::Mpc,
            )
            .await?;

        self.decode_blind(keystream_ref.clone()).await?;

        // Verify the plaintext encrypts back to ciphertext
        let plaintext_ids = self.plaintext_ids(ciphertext.len());
        let ciphertext_ref = self
            .apply_keystream(
                InputText::Blind { ids: plaintext_ids },
                keystream_ref,
                ExecutionMode::Verify,
            )
            .await?;

        self.verify(ciphertext_ref, ciphertext.into()).await?;

        Ok(())
    }

    async fn prove_plaintext(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, StreamCipherError> {
        let KeyAndIv { key, iv } = self
            .state
            .key_iv
            .clone()
            .ok_or(StreamCipherError::KeyIvNotSet)?;

        let plaintext = C::apply_keystream(
            &key,
            &iv,
            self.config.start_ctr,
            &explicit_nonce,
            &ciphertext,
        )?;

        // Prove plaintext encrypts back to ciphertext
        let keystream = self
            .compute_keystream(
                explicit_nonce,
                self.config.start_ctr,
                plaintext.len(),
                ExecutionMode::Prove,
            )
            .await?;

        let plaintext_ids = self.plaintext_ids(plaintext.len());
        let ciphertext = self
            .apply_keystream(
                InputText::Private {
                    ids: plaintext_ids,
                    text: plaintext.clone(),
                },
                keystream,
                ExecutionMode::Prove,
            )
            .await?;

        self.prove(ciphertext).await?;

        Ok(plaintext)
    }

    async fn verify_plaintext(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<(), StreamCipherError> {
        let keystream = self
            .compute_keystream(
                explicit_nonce,
                self.config.start_ctr,
                ciphertext.len(),
                ExecutionMode::Verify,
            )
            .await?;

        let plaintext_ids = self.plaintext_ids(ciphertext.len());
        let ciphertext_ref = self
            .apply_keystream(
                InputText::Blind { ids: plaintext_ids },
                keystream,
                ExecutionMode::Verify,
            )
            .await?;

        self.verify(ciphertext_ref, ciphertext.into()).await?;

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "info", skip(self), err)
    )]
    async fn share_keystream_block(
        &mut self,
        explicit_nonce: Vec<u8>,
        ctr: usize,
    ) -> Result<Vec<u8>, StreamCipherError> {
        let EncodedKeyAndIv { key, iv } = self
            .state
            .encoded_key_iv
            .clone()
            .ok_or(StreamCipherError::KeyIvNotSet)?;

        let explicit_nonce_len = explicit_nonce.len();
        let explicit_nonce: C::NONCE = explicit_nonce.try_into().map_err(|_| {
            StreamCipherError::InvalidExplicitNonceLength {
                expected: C::NONCE_LEN,
                actual: explicit_nonce_len,
            }
        })?;

        let block_id = self.state.execution_id.increment_in_place();
        let mut scope = self.thread_pool.new_scope();
        scope.push(move |thread| {
            Box::pin(async move {
                let key_block = compute_key_block(
                    thread,
                    block_id,
                    KeyBlockConfig::<C>::new(key, iv, explicit_nonce, ctr as u32),
                    ExecutionMode::Mpc,
                )
                .await?;

                let share = thread
                    .decode_shared(&[key_block])
                    .await?
                    .into_iter()
                    .next()
                    .unwrap();

                Ok::<_, StreamCipherError>(share)
            })
        });

        let share: Vec<u8> = scope
            .wait()
            .await
            .into_iter()
            .next()
            .unwrap()?
            .try_into()
            .expect("share is an array");

        Ok(share)
    }
}

#[derive(Debug, Clone, Copy)]
enum ExecutionMode {
    Mpc,
    Prove,
    Verify,
}

async fn apply_keystream<T: Memory + Execute + Prove + Verify + Decode + DecodePrivate + Send>(
    thread: &mut T,
    mode: ExecutionMode,
    execution_id: NestedId,
    input_text: InputText,
    keystream: ValueRef,
) -> Result<ValueRef, StreamCipherError> {
    let input_text = match input_text {
        InputText::Public { ids, text } => {
            let refs = text
                .into_iter()
                .zip(ids)
                .map(|(byte, id)| {
                    let value_ref = thread.new_public_input::<u8>(&id)?;
                    thread.assign(&value_ref, byte)?;

                    Ok::<_, StreamCipherError>(value_ref)
                })
                .collect::<Result<Vec<_>, _>>()?;
            thread.array_from_values(&refs)?
        }
        InputText::Private { ids, text } => {
            let refs = text
                .into_iter()
                .zip(ids)
                .map(|(byte, id)| {
                    let value_ref = thread.new_private_input::<u8>(&id)?;
                    thread.assign(&value_ref, byte)?;

                    Ok::<_, StreamCipherError>(value_ref)
                })
                .collect::<Result<Vec<_>, _>>()?;
            thread.array_from_values(&refs)?
        }
        InputText::Blind { ids } => {
            let refs = ids
                .into_iter()
                .map(|id| thread.new_blind_input::<u8>(&id))
                .collect::<Result<Vec<_>, _>>()?;
            thread.array_from_values(&refs)?
        }
    };

    let output_text = thread.new_array_output::<u8>(
        &execution_id.append_string("output").to_string(),
        input_text.len(),
    )?;

    let circ = build_array_xor(input_text.len());

    match mode {
        ExecutionMode::Mpc => {
            thread
                .execute(circ, &[input_text, keystream], &[output_text.clone()])
                .await?;
        }
        ExecutionMode::Prove => {
            thread
                .execute_prove(circ, &[input_text, keystream], &[output_text.clone()])
                .await?;
        }
        ExecutionMode::Verify => {
            thread
                .execute_verify(circ, &[input_text, keystream], &[output_text.clone()])
                .await?;
        }
    }

    Ok(output_text)
}

#[cfg_attr(
    feature = "tracing",
    tracing::instrument(level = "trace", skip(thread_pool), err)
)]
async fn compute_keystream<
    T: Thread + Memory + Execute + Prove + Verify + Decode + DecodePrivate + Send + 'static,
    C: CtrCircuit,
>(
    thread_pool: &mut ThreadPool<T>,
    execution_id: NestedId,
    configs: Vec<KeyBlockConfig<C>>,
    len: usize,
    mode: ExecutionMode,
) -> Result<ValueRef, StreamCipherError> {
    let mut block_id = execution_id.append_counter();
    let mut scope = thread_pool.new_scope();

    for config in configs {
        let block_id = block_id.increment_in_place();
        scope.push(move |thread| Box::pin(compute_key_block(thread, block_id, config, mode)));
    }

    let key_blocks = scope
        .wait()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    // Flatten the key blocks into a single array.
    let keystream = key_blocks
        .iter()
        .flat_map(|block| block.iter())
        .take(len)
        .cloned()
        .map(|id| ValueRef::Value { id })
        .collect::<Vec<_>>();

    let mut scope = thread_pool.new_scope();
    scope.push(move |thread| Box::pin(async move { thread.array_from_values(&keystream) }));

    let keystream = scope.wait().await.into_iter().next().unwrap()?;

    Ok(keystream)
}

#[cfg_attr(
    feature = "tracing",
    tracing::instrument(level = "trace", skip(thread), err)
)]
async fn compute_key_block<
    T: Memory + Execute + Prove + Verify + Decode + DecodePrivate + Send,
    C: CtrCircuit,
>(
    thread: &mut T,
    block_id: NestedId,
    config: KeyBlockConfig<C>,
    mode: ExecutionMode,
) -> Result<ValueRef, StreamCipherError> {
    let KeyBlockConfig {
        key,
        iv,
        explicit_nonce,
        ctr,
        ..
    } = config;

    let explicit_nonce_ref = thread.new_public_input::<<C as CtrCircuit>::NONCE>(
        &block_id.append_string("explicit_nonce").to_string(),
    )?;
    let ctr_ref = thread.new_public_input::<[u8; 4]>(&block_id.append_string("ctr").to_string())?;
    let key_block =
        thread.new_output::<C::BLOCK>(&block_id.append_string("key_block").to_string())?;

    thread.assign(&explicit_nonce_ref, explicit_nonce)?;
    thread.assign(&ctr_ref, ctr.to_be_bytes())?;

    // Execute circuit
    match mode {
        ExecutionMode::Mpc => {
            thread
                .execute(
                    C::circuit(),
                    &[key, iv, explicit_nonce_ref, ctr_ref],
                    &[key_block.clone()],
                )
                .await?;
        }
        ExecutionMode::Prove => {
            thread
                .execute_prove(
                    C::circuit(),
                    &[key, iv, explicit_nonce_ref, ctr_ref],
                    &[key_block.clone()],
                )
                .await?;
        }
        ExecutionMode::Verify => {
            thread
                .execute_verify(
                    C::circuit(),
                    &[key, iv, explicit_nonce_ref, ctr_ref],
                    &[key_block.clone()],
                )
                .await?;
        }
    }

    Ok(key_block)
}
