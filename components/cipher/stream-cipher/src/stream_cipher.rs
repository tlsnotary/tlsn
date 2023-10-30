use async_trait::async_trait;
use std::{collections::HashMap, fmt::Debug, marker::PhantomData};

use mpz_garble::{
    value::ValueRef, Decode, DecodePrivate, Execute, Memory, MemoryError, Prove, Thread,
    ThreadPool, Verify,
};
use utils::id::NestedId;

use crate::{
    cipher::CtrCircuit,
    circuit::build_array_xor,
    config::{InputText, KeyBlockConfig, OutputTextConfig, StreamCipherConfig},
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
    /// Key and IV for the cipher.
    key_iv: Option<KeyAndIv>,
    /// Unique identifier for each execution of the cipher.
    execution_id: NestedId,
    /// Unique identifier for each byte in the transcript.
    transcript_counter: NestedId,
    /// Unique identifier for each byte in the keystream (prefixed with execution id).
    keystream_counter: NestedId,
    /// Unique identifier for each byte in the ciphertext (prefixed with execution id).
    ciphertext_counter: NestedId,
    /// Unique identifier for bytes we don't care to track (prefixed with execution id).
    opaque_counter: NestedId,
    /// Persists the transcript counter for each transcript id.
    transcript_state: HashMap<String, NestedId>,
}

#[derive(Clone)]
struct KeyAndIv {
    key: ValueRef,
    iv: ValueRef,
}

impl<C, E> MpcStreamCipher<C, E>
where
    C: CtrCircuit,
    E: Thread + Execute + Prove + Verify + Decode + DecodePrivate + Send + Sync + 'static,
{
    /// Creates a new counter-mode cipher.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "info", skip(thread_pool))
    )]
    pub fn new(config: StreamCipherConfig, thread_pool: ThreadPool<E>) -> Self {
        let execution_id = NestedId::new(&config.id).append_counter();
        let transcript_counter = NestedId::new(&config.transcript_id).append_counter();
        let keystream_counter = execution_id.append_string("keystream").append_counter();
        let ciphertext_counter = execution_id.append_string("ciphertext").append_counter();
        let opaque_counter = execution_id.append_string("opaque").append_counter();

        Self {
            config,
            state: State {
                key_iv: None,
                execution_id,
                transcript_counter,
                keystream_counter,
                ciphertext_counter,
                opaque_counter,
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

    /// Returns unique identifiers for the next bytes in the keystream.
    fn keystream_ids(&mut self, len: usize) -> Vec<String> {
        (0..len)
            .map(|_| {
                self.state
                    .keystream_counter
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

    /// Returns unique identifiers for bytes we don't care to track.
    fn opaque_ids(&mut self, len: usize) -> Vec<String> {
        (0..len)
            .map(|_| self.state.opaque_counter.increment_in_place().to_string())
            .collect()
    }

    /// Applies the keystream to the provided input text.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip(self), err)
    )]
    async fn apply_keystream(
        &mut self,
        explicit_nonce: Vec<u8>,
        start_ctr: usize,
        mut input_text_config: InputText,
        mut output_text_config: OutputTextConfig,
    ) -> Result<Option<Vec<u8>>, StreamCipherError> {
        let KeyAndIv { key, iv } = self
            .state
            .key_iv
            .clone()
            .ok_or(StreamCipherError::KeyIvNotSet)?;

        let explicit_nonce_len = explicit_nonce.len();
        let explicit_nonce: C::NONCE = explicit_nonce.try_into().map_err(|_| {
            StreamCipherError::InvalidExplicitNonceLength {
                expected: C::NONCE_LEN,
                actual: explicit_nonce_len,
            }
        })?;

        let text_len = input_text_config.len();
        // Divide msg length by block size rounding up
        let block_count = (text_len / C::BLOCK_LEN) + (text_len % C::BLOCK_LEN != 0) as usize;
        let padding_len = block_count * C::BLOCK_LEN - text_len;

        // Append 0-byte padding to the input text
        input_text_config.append_padding(self.opaque_ids(padding_len));
        // Append 0-byte padding to the output text
        output_text_config.append_padding(self.opaque_ids(padding_len));

        let block_configs = (0..block_count)
            .map(|i| {
                KeyBlockConfig::<C>::new(
                    key.clone(),
                    iv.clone(),
                    explicit_nonce,
                    (start_ctr + i) as u32,
                    input_text_config.drain(C::BLOCK_LEN),
                    output_text_config.drain(C::BLOCK_LEN),
                )
            })
            .collect::<Vec<_>>();

        let execution_id = self.state.execution_id.increment_in_place();

        let mut output_text =
            apply_keystream(&mut self.thread_pool, execution_id, block_configs).await?;

        // Truncate the output text to the length of the input text
        if let Some(output_text) = output_text.as_mut() {
            output_text.truncate(text_len);
        }

        Ok(output_text)
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "debug", skip(self), err)
    )]
    async fn plaintext_proof(
        &mut self,
        plaintext_config: InputText,
        keystream_config: InputText,
        ciphertext_config: InputText,
        role: Role,
    ) -> Result<(), StreamCipherError> {
        let mut scope = self.thread_pool.new_scope();

        scope.push(move |thread| {
            Box::pin(plaintext_proof(
                thread,
                plaintext_config,
                keystream_config,
                ciphertext_config,
                role,
            ))
        });

        scope
            .wait()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        Ok(())
    }
}

#[async_trait]
impl<C, E> StreamCipher<C> for MpcStreamCipher<C, E>
where
    C: CtrCircuit,
    E: Thread + Execute + Prove + Verify + Decode + DecodePrivate + Send + Sync + 'static,
{
    #[cfg_attr(feature = "tracing", tracing::instrument(level = "info", skip(self)))]
    fn set_key(&mut self, key: ValueRef, iv: ValueRef) {
        self.state.key_iv = Some(KeyAndIv { key, iv });
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(level = "debug", skip(self)))]
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
        let plaintext_ids = self.plaintext_ids(plaintext.len());
        let ciphertext_ids = self.ciphertext_ids(plaintext.len());
        self.apply_keystream(
            explicit_nonce,
            self.config.start_ctr,
            InputText::Public {
                ids: plaintext_ids,
                text: plaintext,
            },
            OutputTextConfig::Public {
                ids: ciphertext_ids,
            },
        )
        .await
        .map(|output_text| output_text.expect("output text is set"))
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
        let plaintext_ids = self.plaintext_ids(plaintext.len());
        let ciphertext_ids = self.ciphertext_ids(plaintext.len());
        self.apply_keystream(
            explicit_nonce,
            self.config.start_ctr,
            InputText::Private {
                ids: plaintext_ids,
                text: plaintext,
            },
            OutputTextConfig::Public {
                ids: ciphertext_ids,
            },
        )
        .await
        .map(|output_text| output_text.expect("output text is set"))
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
        let plaintext_ids = self.plaintext_ids(len);
        let ciphertext_ids = self.ciphertext_ids(len);
        self.apply_keystream(
            explicit_nonce,
            self.config.start_ctr,
            InputText::Blind { ids: plaintext_ids },
            OutputTextConfig::Public {
                ids: ciphertext_ids,
            },
        )
        .await
        .map(|output_text| output_text.expect("output text is set"))
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
        let ciphertext_ids = self.ciphertext_ids(ciphertext.len());
        let keystream_ids = self.keystream_ids(ciphertext.len());

        self.apply_keystream(
            explicit_nonce,
            self.config.start_ctr,
            InputText::Public {
                ids: ciphertext_ids,
                text: ciphertext,
            },
            OutputTextConfig::Public { ids: keystream_ids },
        )
        .await
        .map(|output_text| output_text.expect("output text is set"))
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
        let opaque_ids = self.opaque_ids(ciphertext.len());
        let keystream_ids = self.keystream_ids(ciphertext.len());
        let ciphertext_ids = self.ciphertext_ids(ciphertext.len());
        // Compute the keystream, hiding it from the other party(s).
        let keystream = self
            .apply_keystream(
                explicit_nonce,
                self.config.start_ctr,
                InputText::Public {
                    ids: opaque_ids,
                    text: vec![0u8; ciphertext.len()],
                },
                OutputTextConfig::Private {
                    ids: keystream_ids.clone(),
                },
            )
            .await?
            .expect("output text is set");

        let mut plaintext = ciphertext.clone();
        plaintext
            .iter_mut()
            .zip(keystream.iter())
            .for_each(|(c, k)| *c ^= k);

        let plaintext_config = InputText::Private {
            ids: self.plaintext_ids(plaintext.len()),
            text: plaintext.clone(),
        };
        let keystream_config = InputText::Blind { ids: keystream_ids };
        let ciphertext_config = InputText::Public {
            ids: ciphertext_ids,
            text: ciphertext,
        };

        // Prove to the other party(s) that the plaintext is correct.
        self.plaintext_proof(
            plaintext_config,
            keystream_config,
            ciphertext_config,
            Role::Prover,
        )
        .await?;

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
        let opaque_ids = self.opaque_ids(ciphertext.len());
        let keystream_ids = self.keystream_ids(ciphertext.len());
        let ciphertext_ids = self.ciphertext_ids(ciphertext.len());
        // Compute the keystream, not revealing it to this party.
        _ = self
            .apply_keystream(
                explicit_nonce,
                self.config.start_ctr,
                InputText::Public {
                    ids: opaque_ids,
                    text: vec![0u8; ciphertext.len()],
                },
                OutputTextConfig::Blind {
                    ids: keystream_ids.clone(),
                },
            )
            .await?;

        let plaintext_config = InputText::Blind {
            ids: self.plaintext_ids(ciphertext.len()),
        };
        let keystream_config = InputText::Blind { ids: keystream_ids };
        let ciphertext_config = InputText::Public {
            ids: ciphertext_ids,
            text: ciphertext,
        };

        // Verify the plaintext purported by the other party is correct.
        self.plaintext_proof(
            plaintext_config,
            keystream_config,
            ciphertext_config,
            Role::Verifier,
        )
        .await?;

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
        let opaque_input_ids = self.opaque_ids(C::BLOCK_LEN);
        let opaque_output_ids = self.opaque_ids(C::BLOCK_LEN);
        self.apply_keystream(
            explicit_nonce,
            ctr,
            InputText::Public {
                ids: opaque_input_ids,
                text: vec![0u8; C::BLOCK_LEN],
            },
            OutputTextConfig::Shared {
                ids: opaque_output_ids,
            },
        )
        .await
        .map(|output_text| output_text.expect("output text is set"))
    }
}

#[derive(Debug)]
enum Role {
    Prover,
    Verifier,
}

#[cfg_attr(
    feature = "tracing",
    tracing::instrument(level = "trace", skip(thread), err)
)]
async fn plaintext_proof<T: Thread + Memory + Prove + Verify + Decode + DecodePrivate + 'static>(
    thread: &mut T,
    plaintext_config: InputText,
    keystream_config: InputText,
    ciphertext_config: InputText,
    role: Role,
) -> Result<(), StreamCipherError> {
    let circ = build_array_xor(plaintext_config.len());

    let plaintext = match plaintext_config {
        InputText::Public { ids, text } => text
            .into_iter()
            .zip(ids)
            .map(|(byte, id)| {
                let byte_ref = thread.new_public_input::<u8>(&id)?;
                thread.assign(&byte_ref, byte)?;
                Ok(byte_ref)
            })
            .collect::<Result<Vec<_>, MemoryError>>()?,
        InputText::Private { ids, text } => text
            .into_iter()
            .zip(ids)
            .map(|(byte, id)| {
                let byte_ref = thread.new_private_input::<u8>(&id)?;
                thread.assign(&byte_ref, byte)?;
                Ok(byte_ref)
            })
            .collect::<Result<Vec<_>, MemoryError>>()?,
        InputText::Blind { ids } => ids
            .iter()
            .map(|id| thread.new_blind_input::<u8>(id))
            .collect::<Result<Vec<_>, MemoryError>>()?,
    };

    // Collect into a single array.
    let plaintext = thread.array_from_values(&plaintext)?;

    let keystream = match keystream_config {
        InputText::Blind { ids } => ids
            .into_iter()
            .map(|id| {
                thread
                    .get_value(&id)
                    .ok_or_else(|| StreamCipherError::MissingValue(id))
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => unreachable!("keystream should already be computed"),
    };

    // Collect into a single array.
    let keystream = thread.array_from_values(&keystream)?;

    let (ciphertext, expected_ciphertext) = match ciphertext_config {
        InputText::Public { ids, text } => (
            ids.iter()
                .map(|id| thread.new_output::<u8>(id))
                .collect::<Result<Vec<_>, _>>()?,
            text,
        ),
        _ => unreachable!("ciphertext is always public"),
    };

    // Collect into a single array.
    let ciphertext = thread.array_from_values(&ciphertext)?;

    match role {
        Role::Prover => {
            thread
                .prove(circ, &[plaintext, keystream], &[ciphertext])
                .await?
        }
        Role::Verifier => {
            thread
                .verify(
                    circ,
                    &[plaintext, keystream],
                    &[ciphertext],
                    &[expected_ciphertext.into()],
                )
                .await?
        }
    }

    Ok(())
}

#[cfg_attr(
    feature = "tracing",
    tracing::instrument(level = "trace", skip(thread_pool), err)
)]
async fn apply_keystream<
    T: Thread + Memory + Execute + Decode + DecodePrivate + Send + 'static,
    C: CtrCircuit,
>(
    thread_pool: &mut ThreadPool<T>,
    execution_id: NestedId,
    configs: Vec<KeyBlockConfig<C>>,
) -> Result<Option<Vec<u8>>, StreamCipherError> {
    let mut block_id = execution_id.append_counter();
    let mut scope = thread_pool.new_scope();

    for config in configs {
        let block_id = block_id.increment_in_place();
        scope.push(move |thread| Box::pin(apply_keyblock(thread, block_id, config)));
    }

    let blocks = scope
        .wait()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    // Flatten the blocks into a single vector.
    let output = blocks.into_iter().flatten().flatten().collect::<Vec<u8>>();

    if output.is_empty() {
        Ok(None)
    } else {
        Ok(Some(output))
    }
}

#[cfg_attr(
    feature = "tracing",
    tracing::instrument(level = "trace", skip(thread), err)
)]
async fn apply_keyblock<T: Memory + Execute + Decode + DecodePrivate + Send, C: CtrCircuit>(
    thread: &mut T,
    block_id: NestedId,
    config: KeyBlockConfig<C>,
) -> Result<Option<Vec<u8>>, StreamCipherError> {
    let KeyBlockConfig {
        key,
        iv,
        explicit_nonce,
        ctr,
        input_text_config,
        output_text_config,
        ..
    } = config;

    let explicit_nonce_ref = thread.new_public_input::<<C as CtrCircuit>::NONCE>(
        &block_id.append_string("explicit_nonce").to_string(),
    )?;
    let ctr_ref = thread.new_public_input::<[u8; 4]>(&block_id.append_string("ctr").to_string())?;

    thread.assign(&explicit_nonce_ref, explicit_nonce)?;
    thread.assign(&ctr_ref, ctr.to_be_bytes())?;

    // Sets up the input text values.
    let input_values = match input_text_config {
        InputText::Public { ids, text } => text
            .into_iter()
            .zip(ids)
            .map(|(byte, id)| {
                let byte_ref = thread.new_public_input::<u8>(&id)?;
                thread.assign(&byte_ref, byte)?;
                Ok(byte_ref)
            })
            .collect::<Result<Vec<_>, MemoryError>>()?,
        InputText::Private { ids, text } => text
            .into_iter()
            .zip(ids)
            .map(|(byte, id)| {
                let byte_ref = thread.new_private_input::<u8>(&id)?;
                thread.assign(&byte_ref, byte)?;
                Ok(byte_ref)
            })
            .collect::<Result<Vec<_>, MemoryError>>()?,
        InputText::Blind { ids } => ids
            .iter()
            .map(|id| thread.new_blind_input::<u8>(id))
            .collect::<Result<Vec<_>, MemoryError>>()?,
    };

    // Concatenate the values into a single block
    let input_block = thread.array_from_values(&input_values)?;

    // Set up the output text values.
    let output_values = match &output_text_config {
        OutputTextConfig::Public { ids } => ids
            .iter()
            .map(|id| thread.new_output::<u8>(id))
            .collect::<Result<Vec<_>, _>>()?,
        OutputTextConfig::Private { ids } => ids
            .iter()
            .map(|id| thread.new_output::<u8>(id))
            .collect::<Result<Vec<_>, _>>()?,
        OutputTextConfig::Blind { ids } => ids
            .iter()
            .map(|id| thread.new_output::<u8>(id))
            .collect::<Result<Vec<_>, _>>()?,
        OutputTextConfig::Shared { ids } => ids
            .iter()
            .map(|id| thread.new_output::<u8>(id))
            .collect::<Result<Vec<_>, _>>()?,
    };

    // Concatenate the values into a single block
    let output_block = thread.array_from_values(&output_values)?;

    // Execute circuit
    thread
        .execute(
            C::circuit(),
            &[key, iv, explicit_nonce_ref, ctr_ref, input_block],
            &[output_block.clone()],
        )
        .await?;

    // Decodes the output text depending on the configuration.
    let output_text = match output_text_config {
        OutputTextConfig::Public { .. } => Some(
            thread
                .decode(&[output_block])
                .await?
                .pop()
                .expect("output text is present"),
        ),
        OutputTextConfig::Private { .. } => Some(
            thread
                .decode_private(&[output_block])
                .await?
                .pop()
                .expect("output text is present"),
        ),
        OutputTextConfig::Blind { .. } => {
            thread.decode_blind(&[output_block]).await?;
            None
        }
        OutputTextConfig::Shared { .. } => Some(
            thread
                .decode_shared(&[output_block])
                .await?
                .pop()
                .expect("output text is present"),
        ),
    }
    .map(|output_text| {
        // Convert the output text to Vec<u8>
        let output_text: C::BLOCK = if let Ok(output_text) = output_text.try_into() {
            output_text
        } else {
            panic!("output_text should be a block")
        };
        output_text.into()
    });

    Ok(output_text)
}
