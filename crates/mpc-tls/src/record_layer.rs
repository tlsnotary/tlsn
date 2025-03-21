//! TLS record layer.

pub(crate) mod aead;
mod aes_ctr;
mod decrypt;
mod encrypt;

use std::{collections::VecDeque, mem::take, sync::Arc};

use aead::MpcAesGcm;
use futures::TryFutureExt;
use mpz_common::{scoped_futures::ScopedFutureExt, Context, Task};
use mpz_memory_core::{
    binary::{Binary, U8},
    Array,
};
use mpz_vm_core::Vm as VmTrait;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tls_core::{
    cipher::make_tls12_aad,
    msgs::enums::{ContentType, ProtocolVersion},
};
use tlsn_common::transcript::{Record, TlsTranscript};
use tokio::sync::Mutex;
use tracing::{debug, instrument};

use crate::{
    record_layer::{aes_ctr::AesCtr, decrypt::DecryptOp, encrypt::EncryptOp},
    MpcTlsError, Role, Vm,
};
pub(crate) use decrypt::DecryptMode;
pub(crate) use encrypt::EncryptMode;

const MAX_RECORD_SIZE: usize = 1026 * 16;
// This limits how much the leader can cause the follower to allocate.
const MAX_BUFFER_SIZE: usize = (16 * (1 << 20)) / MAX_RECORD_SIZE;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PlainRecord {
    pub(crate) typ: ContentType,
    pub(crate) version: ProtocolVersion,
    pub(crate) plaintext: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EncryptedRecord {
    pub(crate) typ: ContentType,
    pub(crate) version: ProtocolVersion,
    pub(crate) explicit_nonce: Vec<u8>,
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) tag: Option<Vec<u8>>,
}

enum State {
    Init,
    Online {
        recv_otp: Option<Vec<u8>>,
        sent_records: Vec<Record>,
        recv_records: Vec<Record>,
    },
    Complete,
    Error,
}

impl State {
    fn take(&mut self) -> Self {
        std::mem::replace(self, State::Error)
    }
}

/// MPC-TLS record layer.
pub(crate) struct RecordLayer {
    role: Role,
    write_seq: u64,
    read_seq: u64,
    encrypter: Arc<Mutex<MpcAesGcm>>,
    decrypt: Arc<Mutex<MpcAesGcm>>,
    aes_ctr: AesCtr,
    state: State,
    /// Whether the record layer has started processing application data.
    started: bool,

    encrypt_buffer: Vec<EncryptOp>,
    decrypt_buffer: Vec<DecryptOp>,
    encrypted_buffer: VecDeque<EncryptedRecord>,
    decrypted_buffer: VecDeque<PlainRecord>,
}

impl RecordLayer {
    /// Creates a new record layer.
    pub(crate) fn new(role: Role, encrypt: MpcAesGcm, decrypt: MpcAesGcm) -> Self {
        Self {
            role,
            write_seq: 0,
            read_seq: 0,
            encrypter: Arc::new(Mutex::new(encrypt)),
            decrypt: Arc::new(Mutex::new(decrypt)),
            aes_ctr: AesCtr::new(role),
            state: State::Init,
            started: false,
            encrypt_buffer: Vec::new(),
            decrypt_buffer: Vec::new(),
            encrypted_buffer: VecDeque::new(),
            decrypted_buffer: VecDeque::new(),
        }
    }

    /// Allocates resources for the record layer.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    /// * `sent_records` - Number of sent records to allocate.
    /// * `recv_records` - Number of received records to allocate.
    /// * `sent_len` - Total length of sent records to allocate.
    /// * `recv_len` - Total length of received records to allocate.
    pub(crate) fn alloc(
        &mut self,
        vm: &mut dyn VmTrait<Binary>,
        sent_records: usize,
        recv_records: usize,
        sent_len: usize,
        recv_len: usize,
    ) -> Result<(), MpcTlsError> {
        let State::Init = self.state.take() else {
            return Err(MpcTlsError::other("record layer is already allocated"));
        };

        let mut encrypt = self
            .encrypter
            .try_lock()
            .map_err(|_| MpcTlsError::other("encrypt lock is held"))?;

        let mut decrypt = self
            .decrypt
            .try_lock()
            .map_err(|_| MpcTlsError::other("decrypt lock is held"))?;

        encrypt
            .alloc(vm, sent_records, sent_len)
            .map_err(MpcTlsError::record_layer)?;

        decrypt
            .alloc(vm, recv_records, recv_len)
            .map_err(MpcTlsError::record_layer)?;

        let recv_otp = match self.role {
            Role::Leader => {
                let mut recv_otp = vec![0u8; recv_len];
                rand::rng().fill_bytes(&mut recv_otp);

                Some(recv_otp)
            }
            Role::Follower => None,
        };

        self.aes_ctr.alloc(vm)?;

        self.state = State::Online {
            recv_otp,
            sent_records: Vec::new(),
            recv_records: Vec::new(),
        };

        Ok(())
    }

    pub(crate) async fn preprocess(&mut self, ctx: &mut Context) -> Result<(), MpcTlsError> {
        let mut encrypt = self
            .encrypter
            .clone()
            .try_lock_owned()
            .map_err(|_| MpcTlsError::other("encrypt lock is held"))?;
        let mut decrypt = self
            .decrypt
            .clone()
            .try_lock_owned()
            .map_err(|_| MpcTlsError::other("decrypt lock is held"))?;

        // Computes GHASH keys in parallel.
        ctx.try_join(
            |ctx| async move { encrypt.preprocess(ctx).await }.scope_boxed(),
            |ctx| async move { decrypt.preprocess(ctx).await }.scope_boxed(),
        )
        .await
        .map_err(MpcTlsError::record_layer)?
        .map_err(MpcTlsError::record_layer)?;

        Ok(())
    }

    /// Sets the keys for the record layer.
    pub(crate) fn set_keys(
        &mut self,
        client_write_key: Array<U8, 16>,
        client_iv: Array<U8, 4>,
        server_write_key: Array<U8, 16>,
        server_iv: Array<U8, 4>,
    ) -> Result<(), MpcTlsError> {
        let mut encrypt = self
            .encrypter
            .try_lock()
            .map_err(|_| MpcTlsError::other("encrypt lock is held"))?;
        let mut decrypt = self
            .decrypt
            .try_lock()
            .map_err(|_| MpcTlsError::other("decrypt lock is held"))?;

        encrypt.set_key(client_write_key);
        encrypt.set_iv(client_iv);
        decrypt.set_key(server_write_key);
        decrypt.set_iv(server_iv);
        self.aes_ctr.set_key(server_write_key, server_iv);

        Ok(())
    }

    /// Sets up the record layer.
    pub(crate) async fn setup(&mut self, ctx: &mut Context) -> Result<(), MpcTlsError> {
        let mut encrypt = self
            .encrypter
            .clone()
            .try_lock_owned()
            .map_err(|_| MpcTlsError::other("encrypt lock is held"))?;
        let mut decrypt = self
            .decrypt
            .clone()
            .try_lock_owned()
            .map_err(|_| MpcTlsError::other("decrypt lock is held"))?;

        // Computes GHASH keys in parallel.
        ctx.try_join(
            |ctx| async move { encrypt.setup(ctx).await }.scope_boxed(),
            |ctx| async move { decrypt.setup(ctx).await }.scope_boxed(),
        )
        .await
        .map_err(MpcTlsError::record_layer)?
        .map_err(MpcTlsError::record_layer)?;

        Ok(())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.encrypt_buffer.is_empty()
            && self.decrypt_buffer.is_empty()
            && self.encrypted_buffer.is_empty()
            && self.decrypted_buffer.is_empty()
    }

    pub(crate) fn wants_flush(&self) -> bool {
        !self.encrypt_buffer.is_empty() || !self.decrypt_buffer.is_empty()
    }

    pub(crate) fn start_traffic(&mut self) {
        self.started = true;
        debug!("started processing application data");
    }

    pub(crate) fn push_encrypt(
        &mut self,
        typ: ContentType,
        version: ProtocolVersion,
        len: usize,
        plaintext: Option<Vec<u8>>,
        mode: EncryptMode,
    ) -> Result<(), MpcTlsError> {
        if self.encrypt_buffer.len() >= MAX_BUFFER_SIZE {
            return Err(MpcTlsError::peer("encrypt buffer is full"));
        }

        let (seq, explicit_nonce, aad) = self.next_write(typ, version, len);
        self.encrypt_buffer.push(EncryptOp::new(
            seq,
            typ,
            version,
            len,
            plaintext,
            explicit_nonce,
            aad,
            mode,
        )?);

        Ok(())
    }

    pub(crate) fn push_decrypt(
        &mut self,
        typ: ContentType,
        version: ProtocolVersion,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        tag: Vec<u8>,
        mode: DecryptMode,
    ) -> Result<(), MpcTlsError> {
        if self.decrypt_buffer.len() >= MAX_BUFFER_SIZE {
            return Err(MpcTlsError::peer("decrypt buffer is full"));
        }

        let (seq, aad) = self.next_read(typ, version, ciphertext.len());
        self.decrypt_buffer.push(DecryptOp::new(
            seq,
            typ,
            version,
            explicit_nonce,
            ciphertext,
            aad,
            tag,
            mode,
        ));

        Ok(())
    }

    /// Returns the next encrypted record.
    pub(crate) fn next_encrypted(&mut self) -> Option<EncryptedRecord> {
        let typ = self.encrypted_buffer.front().map(|r| r.typ)?;
        // If we haven't started processing application data we return None.
        if !self.started && typ == ContentType::ApplicationData {
            None
        } else {
            self.encrypted_buffer.pop_front()
        }
    }

    /// Returns the next decrypted record.
    pub(crate) fn next_decrypted(&mut self) -> Option<PlainRecord> {
        let typ = self.decrypted_buffer.front().map(|r| r.typ)?;
        // If we haven't started processing application data we return None.
        if !self.started && typ == ContentType::ApplicationData {
            None
        } else {
            self.decrypted_buffer.pop_front()
        }
    }

    #[instrument(level = "debug", skip(self, ctx, vm), err)]
    pub(crate) async fn flush(
        &mut self,
        ctx: &mut Context,
        vm: Vm,
        is_decrypting: bool,
    ) -> Result<(), MpcTlsError> {
        let State::Online {
            recv_otp,
            sent_records,
            recv_records,
            ..
        } = &mut self.state
        else {
            return Err(MpcTlsError::state(
                "record layer must be in online state to flush",
            ));
        };

        let mut vm = vm
            .try_lock_owned()
            .map_err(|_| MpcTlsError::record_layer("VM lock is held"))?;

        let mut encrypter = self
            .encrypter
            .try_lock()
            .map_err(|_| MpcTlsError::record_layer("encrypt lock is held"))?;

        let mut decrypter = self
            .decrypt
            .try_lock()
            .map_err(|_| MpcTlsError::record_layer("decrypt lock is held"))?;

        let encrypt_ops: Vec<_> = self.encrypt_buffer.drain(..).collect();
        let decrypt_ops: Vec<_> = if is_decrypting {
            self.decrypt_buffer.drain(..).collect()
        } else {
            // Process non-application data even if we're not decrypting.
            let decrypt_pos = self
                .decrypt_buffer
                .iter()
                .position(|op| op.typ == ContentType::ApplicationData)
                .unwrap_or(self.decrypt_buffer.len());

            self.decrypt_buffer.drain(..decrypt_pos).collect()
        };

        if encrypt_ops.is_empty() && decrypt_ops.is_empty() {
            debug!("no operations to process, skipping");
            return Ok(());
        }

        debug!(
            "processing {} encrypt ops and {} decrypt ops",
            encrypt_ops.len(),
            decrypt_ops.len()
        );

        let (pending_encrypt, compute_tags) =
            encrypt::encrypt(&mut (*vm), &mut encrypter, &encrypt_ops)?;

        let pending_decrypt =
            decrypt::decrypt_mpc(&mut (*vm), &mut decrypter, recv_otp.as_mut(), &decrypt_ops)?;
        let verify_tags = decrypt::verify_tags(&mut (*vm), &mut decrypter, &decrypt_ops)?;

        // Run tag computation and VM in parallel.
        let (mut tags, _, _) = ctx
            .try_join3(
                |ctx| {
                    compute_tags
                        .run(ctx)
                        .map_err(MpcTlsError::record_layer)
                        .scope_boxed()
                },
                |ctx| {
                    verify_tags
                        .run(ctx)
                        .map_err(MpcTlsError::record_layer)
                        .scope_boxed()
                },
                |ctx| {
                    async move { vm.execute_all(ctx).map_err(MpcTlsError::record_layer).await }
                        .scope_boxed()
                },
            )
            .await
            .map_err(MpcTlsError::record_layer)??;

        // Reverse tags, as we will be popping from the back.
        if let Some(tags) = tags.as_mut() {
            tags.reverse();
        }

        for (op, pending) in encrypt_ops.into_iter().zip(pending_encrypt) {
            let ciphertext = pending.output.try_encrypt()?;
            self.encrypted_buffer.push_back(EncryptedRecord {
                typ: op.typ,
                version: op.version,
                explicit_nonce: op.explicit_nonce.clone(),
                ciphertext: ciphertext.clone(),
                tag: tags.as_mut().and_then(Vec::pop),
            });

            sent_records.push(Record {
                seq: op.seq,
                typ: op.typ,
                plaintext: op.plaintext,
                plaintext_ref: pending.plaintext_ref,
                explicit_nonce: op.explicit_nonce,
                ciphertext,
            });
        }

        for (op, pending) in decrypt_ops.into_iter().zip(pending_decrypt) {
            let plaintext = pending.output.try_decrypt()?;
            self.decrypted_buffer.push_back(PlainRecord {
                typ: op.typ,
                version: op.version,
                plaintext: plaintext.clone(),
            });

            recv_records.push(Record {
                seq: op.seq,
                typ: op.typ,
                plaintext,
                plaintext_ref: None,
                explicit_nonce: op.explicit_nonce,
                ciphertext: op.ciphertext,
            });
        }

        Ok(())
    }

    pub(crate) async fn commit(
        &mut self,
        ctx: &mut Context,
        vm: Vm,
    ) -> Result<TlsTranscript, MpcTlsError> {
        let State::Online {
            sent_records,
            mut recv_records,
            ..
        } = self.state.take()
        else {
            return Err(MpcTlsError::state(
                "record layer must be in online state to commit",
            ));
        };

        if !self.encrypt_buffer.is_empty() {
            return Err(MpcTlsError::state(
                "record layer can not commit with pending encrypt operations",
            ));
        }

        let mut vm = vm
            .try_lock_owned()
            .map_err(|_| MpcTlsError::record_layer("VM lock is held"))?;

        let mut decrypter = self
            .decrypt
            .try_lock()
            .map_err(|_| MpcTlsError::record_layer("decrypt lock is held"))?;

        let buffered_ops = take(&mut self.decrypt_buffer);

        // Verify tags of buffered ciphertexts.
        let verify_tags = decrypt::verify_tags(&mut (*vm), &mut decrypter, &buffered_ops)?;

        vm.execute_all(ctx)
            .await
            .map_err(MpcTlsError::record_layer)?;

        verify_tags
            .run(ctx)
            .await
            .map_err(MpcTlsError::record_layer)?;

        // Reveal decrypt key to the leader.
        self.aes_ctr.decode_key(&mut (*vm))?;
        vm.flush(ctx).await.map_err(MpcTlsError::record_layer)?;
        self.aes_ctr.finish_decode()?;

        let pending_decrypts = decrypt::decrypt_local(
            self.role,
            &mut (*vm),
            &mut decrypter,
            &mut self.aes_ctr,
            &buffered_ops,
        )?;

        vm.execute_all(ctx)
            .await
            .map_err(MpcTlsError::record_layer)?;

        for (op, pending) in buffered_ops.into_iter().zip(pending_decrypts) {
            let plaintext = pending.output.try_decrypt()?;
            self.decrypted_buffer.push_back(PlainRecord {
                typ: op.typ,
                version: op.version,
                plaintext: plaintext.clone(),
            });

            recv_records.push(Record {
                seq: op.seq,
                typ: op.typ,
                plaintext,
                plaintext_ref: None,
                explicit_nonce: op.explicit_nonce,
                ciphertext: op.ciphertext,
            });
        }

        self.state = State::Complete;

        Ok(TlsTranscript {
            sent: sent_records,
            recv: recv_records,
        })
    }

    fn next_write(
        &mut self,
        typ: ContentType,
        version: ProtocolVersion,
        len: usize,
    ) -> (u64, Vec<u8>, Vec<u8>) {
        let seq = self.write_seq;
        self.write_seq += 1;
        let explicit_nonce = seq.to_be_bytes().to_vec();
        let aad = make_tls12_aad(seq, typ, version, len).to_vec();

        (seq, explicit_nonce, aad)
    }

    fn next_read(
        &mut self,
        typ: ContentType,
        version: ProtocolVersion,
        len: usize,
    ) -> (u64, Vec<u8>) {
        let seq = self.read_seq;
        self.read_seq += 1;
        let aad = make_tls12_aad(seq, typ, version, len).to_vec();

        (seq, aad)
    }
}

#[derive(Clone)]
pub(crate) struct TagData {
    pub(crate) explicit_nonce: Vec<u8>,
    pub(crate) aad: Vec<u8>,
}
