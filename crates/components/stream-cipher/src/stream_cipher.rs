use async_trait::async_trait;
use mpz_circuits::types::Value;
use std::collections::HashMap;
use tracing::instrument;

use mpz_garble::{value::ValueRef, Decode, DecodePrivate, Execute, Load, Prove, Thread, Verify};
use utils::id::NestedId;

use crate::{
    cipher::CtrCircuit,
    circuit::build_array_xor,
    config::{is_valid_mode, ExecutionMode, InputText, StreamCipherConfig},
    keystream::KeyStream,
    StreamCipher, StreamCipherError,
};

/// An MPC stream cipher.
#[derive(Debug)]
pub struct MpcStreamCipher<C, E>
where
    C: CtrCircuit,
    E: Thread + Execute + Decode + DecodePrivate + Send + Sync,
{
    config: StreamCipherConfig,
    state: State<C>,
    thread: E,
}

struct State<C> {
    /// Encoded key and IV for the cipher.
    encoded_key_iv: Option<EncodedKeyAndIv>,
    /// Key and IV for the cipher.
    key_iv: Option<KeyAndIv>,
    /// Keystream state.
    keystream: KeyStream<C>,
    /// Current transcript.
    transcript: Transcript,
    /// Maps a transcript ID to the corresponding transcript.
    transcripts: HashMap<String, Transcript>,
    /// Number of messages operated on.
    counter: usize,
}

opaque_debug::implement!(State<C>);

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

/// A subset of plaintext bytes processed by the stream cipher.
///
/// Note that `Transcript` does not store the actual bytes. Instead, it provides
/// IDs which are assigned to plaintext bytes of the stream cipher.
struct Transcript {
    /// The ID of this transcript.
    id: String,
    /// The ID for the next plaintext byte.
    plaintext: NestedId,
}

impl Transcript {
    fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            plaintext: NestedId::new(id).append_counter(),
        }
    }

    /// Returns unique identifiers for the next plaintext bytes in the
    /// transcript.
    fn extend_plaintext(&mut self, len: usize) -> Vec<String> {
        (0..len)
            .map(|_| self.plaintext.increment_in_place().to_string())
            .collect()
    }
}

impl<C, E> MpcStreamCipher<C, E>
where
    C: CtrCircuit,
    E: Thread + Execute + Load + Prove + Verify + Decode + DecodePrivate + Send + Sync + 'static,
{
    /// Creates a new counter-mode cipher.
    pub fn new(config: StreamCipherConfig, thread: E) -> Self {
        let keystream = KeyStream::new(&config.id);
        let transcript = Transcript::new(&config.transcript_id);
        Self {
            config,
            state: State {
                encoded_key_iv: None,
                key_iv: None,
                keystream,
                transcript,
                transcripts: HashMap::new(),
                counter: 0,
            },
            thread,
        }
    }

    /// Returns a mutable reference to the underlying thread.
    pub fn thread_mut(&mut self) -> &mut E {
        &mut self.thread
    }

    /// Computes a keystream of the given length.
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
            .as_ref()
            .ok_or_else(StreamCipherError::key_not_set)?;

        let keystream = self
            .state
            .keystream
            .compute(
                &mut self.thread,
                mode,
                key,
                iv,
                explicit_nonce,
                start_ctr,
                len,
            )
            .await?;

        self.state.counter += 1;

        Ok(keystream)
    }

    /// Applies the keystream to the provided input text.
    async fn apply_keystream(
        &mut self,
        mode: ExecutionMode,
        input_text: InputText,
        keystream: ValueRef,
    ) -> Result<ValueRef, StreamCipherError> {
        debug_assert!(
            is_valid_mode(&mode, &input_text),
            "invalid execution mode for input text"
        );

        let input_text = match input_text {
            InputText::Public { ids, text } => {
                let refs = text
                    .into_iter()
                    .zip(ids)
                    .map(|(byte, id)| {
                        let value_ref = self.thread.new_public_input::<u8>(&id)?;
                        self.thread.assign(&value_ref, byte)?;

                        Ok::<_, StreamCipherError>(value_ref)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                self.thread.array_from_values(&refs)?
            }
            InputText::Private { ids, text } => {
                let refs = text
                    .into_iter()
                    .zip(ids)
                    .map(|(byte, id)| {
                        let value_ref = self.thread.new_private_input::<u8>(&id)?;
                        self.thread.assign(&value_ref, byte)?;

                        Ok::<_, StreamCipherError>(value_ref)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                self.thread.array_from_values(&refs)?
            }
            InputText::Blind { ids } => {
                let refs = ids
                    .into_iter()
                    .map(|id| self.thread.new_blind_input::<u8>(&id))
                    .collect::<Result<Vec<_>, _>>()?;
                self.thread.array_from_values(&refs)?
            }
        };

        let output_text = self.thread.new_array_output::<u8>(
            &format!("{}/out/{}", self.config.id, self.state.counter),
            input_text.len(),
        )?;

        let circ = build_array_xor(input_text.len());

        match mode {
            ExecutionMode::Mpc => {
                self.thread
                    .execute(circ, &[input_text, keystream], &[output_text.clone()])
                    .await?;
            }
            ExecutionMode::Prove => {
                self.thread
                    .execute_prove(circ, &[input_text, keystream], &[output_text.clone()])
                    .await?;
            }
            ExecutionMode::Verify => {
                self.thread
                    .execute_verify(circ, &[input_text, keystream], &[output_text.clone()])
                    .await?;
            }
        }

        Ok(output_text)
    }

    async fn decode_public(&mut self, value: ValueRef) -> Result<Value, StreamCipherError> {
        self.thread
            .decode(&[value])
            .await
            .map_err(StreamCipherError::from)
            .map(|mut output| output.pop().unwrap())
    }

    async fn decode_shared(&mut self, value: ValueRef) -> Result<Value, StreamCipherError> {
        self.thread
            .decode_shared(&[value])
            .await
            .map_err(StreamCipherError::from)
            .map(|mut output| output.pop().unwrap())
    }

    async fn decode_private(&mut self, value: ValueRef) -> Result<Value, StreamCipherError> {
        self.thread
            .decode_private(&[value])
            .await
            .map_err(StreamCipherError::from)
            .map(|mut output| output.pop().unwrap())
    }

    async fn decode_blind(&mut self, value: ValueRef) -> Result<(), StreamCipherError> {
        self.thread.decode_blind(&[value]).await?;
        Ok(())
    }

    async fn prove(&mut self, value: ValueRef) -> Result<(), StreamCipherError> {
        self.thread.prove(&[value]).await?;
        Ok(())
    }

    async fn verify(&mut self, value: ValueRef, expected: Value) -> Result<(), StreamCipherError> {
        self.thread.verify(&[value], &[expected]).await?;
        Ok(())
    }
}

#[async_trait]
impl<C, E> StreamCipher<C> for MpcStreamCipher<C, E>
where
    C: CtrCircuit,
    E: Thread + Execute + Load + Prove + Verify + Decode + DecodePrivate + Send + Sync + 'static,
{
    fn set_key(&mut self, key: ValueRef, iv: ValueRef) {
        self.state.encoded_key_iv = Some(EncodedKeyAndIv { key, iv });
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn decode_key_private(&mut self) -> Result<(), StreamCipherError> {
        let EncodedKeyAndIv { key, iv } = self
            .state
            .encoded_key_iv
            .clone()
            .ok_or_else(StreamCipherError::key_not_set)?;

        let [key, iv]: [_; 2] = self
            .thread
            .decode_private(&[key, iv])
            .await?
            .try_into()
            .expect("decoded 2 values");

        let key: Vec<u8> = key.try_into().expect("key is an array");
        let iv: Vec<u8> = iv.try_into().expect("iv is an array");

        self.state.key_iv = Some(KeyAndIv { key, iv });

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn decode_key_blind(&mut self) -> Result<(), StreamCipherError> {
        let EncodedKeyAndIv { key, iv } = self
            .state
            .encoded_key_iv
            .clone()
            .ok_or_else(StreamCipherError::key_not_set)?;

        self.thread.decode_blind(&[key, iv]).await?;

        Ok(())
    }

    fn set_transcript_id(&mut self, id: &str) {
        if id == self.state.transcript.id {
            return;
        }

        let transcript = self
            .state
            .transcripts
            .remove(id)
            .unwrap_or_else(|| Transcript::new(id));
        let old_transcript = std::mem::replace(&mut self.state.transcript, transcript);
        self.state
            .transcripts
            .insert(old_transcript.id.clone(), old_transcript);
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn preprocess(&mut self, len: usize) -> Result<(), StreamCipherError> {
        let EncodedKeyAndIv { key, iv } = self
            .state
            .encoded_key_iv
            .as_ref()
            .ok_or_else(StreamCipherError::key_not_set)?;

        self.state
            .keystream
            .preprocess(&mut self.thread, key, iv, len)
            .await
    }

    #[instrument(level = "debug", skip_all, err)]
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

        let plaintext_ids = self.state.transcript.extend_plaintext(plaintext.len());
        let ciphertext = self
            .apply_keystream(
                ExecutionMode::Mpc,
                InputText::Public {
                    ids: plaintext_ids,
                    text: plaintext,
                },
                keystream,
            )
            .await?;

        let ciphertext: Vec<u8> = self
            .decode_public(ciphertext)
            .await?
            .try_into()
            .expect("ciphertext is array");

        Ok(ciphertext)
    }

    #[instrument(level = "debug", skip_all, err)]
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

        let plaintext_ids = self.state.transcript.extend_plaintext(plaintext.len());
        let ciphertext = self
            .apply_keystream(
                ExecutionMode::Mpc,
                InputText::Private {
                    ids: plaintext_ids,
                    text: plaintext,
                },
                keystream,
            )
            .await?;

        let ciphertext: Vec<u8> = self
            .decode_public(ciphertext)
            .await?
            .try_into()
            .expect("ciphertext is array");

        Ok(ciphertext)
    }

    #[instrument(level = "debug", skip_all, err)]
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

        let plaintext_ids = self.state.transcript.extend_plaintext(len);
        let ciphertext = self
            .apply_keystream(
                ExecutionMode::Mpc,
                InputText::Blind { ids: plaintext_ids },
                keystream,
            )
            .await?;

        let ciphertext: Vec<u8> = self
            .decode_public(ciphertext)
            .await?
            .try_into()
            .expect("ciphertext is array");

        Ok(ciphertext)
    }

    #[instrument(level = "debug", skip_all, err)]
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

        let ciphertext_ids = (0..ciphertext.len())
            .map(|i| format!("ct/{}/{}", self.state.counter, i))
            .collect();
        let plaintext = self
            .apply_keystream(
                ExecutionMode::Mpc,
                InputText::Public {
                    ids: ciphertext_ids,
                    text: ciphertext,
                },
                keystream,
            )
            .await?;

        let plaintext: Vec<u8> = self
            .decode_public(plaintext)
            .await?
            .try_into()
            .expect("plaintext is array");

        Ok(plaintext)
    }

    #[instrument(level = "debug", skip_all, err)]
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

        // Prove plaintext encrypts back to ciphertext.
        let plaintext_ids = self.state.transcript.extend_plaintext(plaintext.len());
        let ciphertext = self
            .apply_keystream(
                ExecutionMode::Prove,
                InputText::Private {
                    ids: plaintext_ids,
                    text: plaintext.clone(),
                },
                keystream_ref,
            )
            .await?;

        self.prove(ciphertext).await?;

        Ok(plaintext)
    }

    #[instrument(level = "debug", skip_all, err)]
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

        // Verify the plaintext encrypts back to ciphertext.
        let plaintext_ids = self.state.transcript.extend_plaintext(ciphertext.len());
        let ciphertext_ref = self
            .apply_keystream(
                ExecutionMode::Verify,
                InputText::Blind { ids: plaintext_ids },
                keystream_ref,
            )
            .await?;

        self.verify(ciphertext_ref, ciphertext.into()).await?;

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn prove_plaintext(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, StreamCipherError> {
        let KeyAndIv { key, iv } = self
            .state
            .key_iv
            .clone()
            .ok_or_else(StreamCipherError::key_not_set)?;

        let plaintext = C::apply_keystream(
            &key,
            &iv,
            self.config.start_ctr,
            &explicit_nonce,
            &ciphertext,
        )?;

        // Prove plaintext encrypts back to ciphertext.
        let keystream = self
            .compute_keystream(
                explicit_nonce,
                self.config.start_ctr,
                plaintext.len(),
                ExecutionMode::Prove,
            )
            .await?;

        let plaintext_ids = self.state.transcript.extend_plaintext(plaintext.len());
        let ciphertext = self
            .apply_keystream(
                ExecutionMode::Prove,
                InputText::Private {
                    ids: plaintext_ids,
                    text: plaintext.clone(),
                },
                keystream,
            )
            .await?;

        self.prove(ciphertext).await?;

        Ok(plaintext)
    }

    #[instrument(level = "debug", skip_all, err)]
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

        let plaintext_ids = self.state.transcript.extend_plaintext(ciphertext.len());
        let ciphertext_ref = self
            .apply_keystream(
                ExecutionMode::Verify,
                InputText::Blind { ids: plaintext_ids },
                keystream,
            )
            .await?;

        self.verify(ciphertext_ref, ciphertext.into()).await?;

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn share_keystream_block(
        &mut self,
        explicit_nonce: Vec<u8>,
        ctr: usize,
    ) -> Result<Vec<u8>, StreamCipherError> {
        let EncodedKeyAndIv { key, iv } = self
            .state
            .encoded_key_iv
            .as_ref()
            .ok_or_else(StreamCipherError::key_not_set)?;

        let key_block = self
            .state
            .keystream
            .compute(
                &mut self.thread,
                ExecutionMode::Mpc,
                key,
                iv,
                explicit_nonce,
                ctr,
                C::BLOCK_LEN,
            )
            .await?;

        let share = self
            .decode_shared(key_block)
            .await?
            .try_into()
            .expect("key block is array");

        Ok(share)
    }
}
