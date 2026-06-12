//! Shared MPC session machinery.
//!
//! [`MpcSession`] owns the MPC primitives that drive a single TLS connection:
//! the key exchange, the PRF and the record layer, together with the VM and
//! the I/O context shared with the peer. Both the leader and the follower
//! embed an [`MpcSession`] and run the *same* MPC operations on it; what
//! differs between them is only the orchestration: the leader decides what to
//! do and announces it over [`crate::msg::Message`], while the follower mirrors
//! those decisions. Keeping the cryptographic operations here ensures the two
//! roles cannot drift apart.

use hmac_sha256::{Prf, PrfOutput};
use key_exchange::KeyExchange;
use mpz_common::Context;
use mpz_core::bitvec::BitVec;
use mpz_memory_core::{DecodeFutureTyped, MemoryExt, binary::Binary};
use mpz_vm_core::Vm as VmTrait;
use tls_core::{
    key::PublicKey,
    msgs::{
        alert::AlertMessagePayload,
        codec::{Codec, Reader},
        enums::{AlertDescription, NamedGroup},
    },
};
use tlsn_core::transcript::{ContentType, Record, TlsTranscript};

use crate::{
    Config, MpcTlsError, SessionKeys, Vm,
    record_layer::{EncryptedRecord, PlainRecord, RecordLayer},
};

/// Length of the explicit nonce prefixing every AES-GCM record.
const EXPLICIT_NONCE_LEN: usize = 8;
/// Length of an AES-GCM authentication tag.
const TAG_LEN: usize = 16;

/// The MPC machinery for a single TLS connection.
///
/// This is the cryptographic heart shared by the leader and follower. It is
/// deliberately agnostic of the wire protocol between them: it exposes the MPC
/// operations as methods, and the role-specific code is responsible for the
/// ordering and the [`crate::msg::Message`] exchange around them.
pub(crate) struct MpcSession {
    ctx: Context,
    vm: Vm,
    ke: Box<dyn KeyExchange + Send + Sync + 'static>,
    prf: Prf,
    record_layer: RecordLayer,
    /// Decode future for the client Finished verify data, populated by
    /// [`MpcSession::alloc`].
    cf_vd_fut: Option<DecodeFutureTyped<BitVec, [u8; 12]>>,
    /// Decode future for the server Finished verify data, populated by
    /// [`MpcSession::alloc`].
    sf_vd_fut: Option<DecodeFutureTyped<BitVec, [u8; 12]>>,
    /// Client Finished verify data, populated by [`MpcSession::compute_cf_vd`].
    cf_vd: Option<[u8; 12]>,
    /// Server Finished verify data, populated by [`MpcSession::compute_sf_vd`].
    sf_vd: Option<[u8; 12]>,
}

impl std::fmt::Debug for MpcSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcSession").finish_non_exhaustive()
    }
}

impl MpcSession {
    /// Creates a new session from its MPC components.
    pub(crate) fn new(
        ctx: Context,
        vm: Vm,
        ke: Box<dyn KeyExchange + Send + Sync + 'static>,
        prf: Prf,
        record_layer: RecordLayer,
    ) -> Self {
        Self {
            ctx,
            vm,
            ke,
            prf,
            record_layer,
            cf_vd_fut: None,
            sf_vd_fut: None,
            cf_vd: None,
            sf_vd: None,
        }
    }

    /// Returns a mutable reference to the I/O context shared with the peer.
    pub(crate) fn ctx_mut(&mut self) -> &mut Context {
        &mut self.ctx
    }

    /// Allocates the MPC resources for the connection: the key exchange, the
    /// PRF and the record layer.
    ///
    /// Returns the session keys; the Finished verify-data decode futures are
    /// retained internally for [`MpcSession::compute_cf_vd`] and
    /// [`MpcSession::compute_sf_vd`].
    pub(crate) fn alloc(&mut self, config: &Config) -> Result<SessionKeys, MpcTlsError> {
        let mut vm = self
            .vm
            .try_lock()
            .map_err(|_| MpcTlsError::other("VM lock is held"))?;

        let pms = self.ke.alloc(&mut *vm)?;
        let PrfOutput { keys, cf_vd, sf_vd } = self.prf.alloc_pms(&mut *vm, pms)?;
        self.record_layer.set_keys(
            keys.client_write_key,
            keys.client_iv,
            keys.server_write_key,
            keys.server_iv,
        )?;

        let cf_vd = vm.decode(cf_vd).map_err(MpcTlsError::alloc)?;
        let sf_vd = vm.decode(sf_vd).map_err(MpcTlsError::alloc)?;

        let server_write_mac_key = self.record_layer.alloc(
            &mut *vm,
            config.max_sent_records,
            config.max_recv_records_online,
            config.max_sent,
            config.max_recv_online,
            config.max_recv,
        )?;

        drop(vm);

        self.cf_vd_fut = Some(cf_vd);
        self.sf_vd_fut = Some(sf_vd);

        Ok(SessionKeys {
            client_write_key: keys.client_write_key,
            client_write_iv: keys.client_iv,
            server_write_key: keys.server_write_key,
            server_write_iv: keys.server_iv,
            server_write_mac_key,
        })
    }

    /// Preprocesses the connection, running the key exchange, record layer and
    /// VM preprocessing concurrently.
    ///
    /// Takes the session by value because the concurrent tasks require owned
    /// `'static` access to the key exchange and record layer.
    pub(crate) async fn preprocess(self) -> Result<Self, MpcTlsError> {
        let MpcSession {
            mut ctx,
            vm,
            ke,
            prf,
            record_layer,
            cf_vd_fut,
            sf_vd_fut,
            cf_vd,
            sf_vd,
        } = self;

        let mut vm_lock = vm
            .clone()
            .try_lock_owned()
            .map_err(|_| MpcTlsError::other("VM lock is held"))?;

        let (ke, record_layer, _) = ctx
            .try_join3(
                move |ctx| {
                    Box::pin(async move {
                        let mut ke = ke;
                        ke.setup(ctx)
                            .await
                            .map(|_| ke)
                            .map_err(MpcTlsError::preprocess)
                    })
                },
                move |ctx| {
                    Box::pin(async move {
                        let mut record_layer = record_layer;
                        record_layer
                            .preprocess(ctx)
                            .await
                            .map(|_| record_layer)
                            .map_err(MpcTlsError::preprocess)
                    })
                },
                move |ctx| {
                    Box::pin(async move {
                        vm_lock
                            .preprocess(ctx)
                            .await
                            .map_err(MpcTlsError::preprocess)?;
                        vm_lock.flush(ctx).await.map_err(MpcTlsError::preprocess)?;

                        Ok::<_, MpcTlsError>(())
                    })
                },
            )
            .await
            .map_err(MpcTlsError::preprocess)??;

        Ok(MpcSession {
            ctx,
            vm,
            ke,
            prf,
            record_layer,
            cf_vd_fut,
            sf_vd_fut,
            cf_vd,
            sf_vd,
        })
    }

    /// Sets the client random in the PRF.
    pub(crate) fn set_client_random(&mut self, random: [u8; 32]) {
        self.prf.set_client_random(random);
    }

    /// Returns the client's ephemeral public key for the key exchange.
    pub(crate) fn client_key_share(&self) -> Result<PublicKey, MpcTlsError> {
        let pk = self.ke.client_key()?;
        Ok(PublicKey::new(
            NamedGroup::secp256r1,
            &p256::EncodedPoint::from(pk).to_bytes(),
        ))
    }

    /// Computes the session keys from the server's handshake parameters and
    /// prepares the record layer for encryption.
    pub(crate) async fn compute_keys(
        &mut self,
        server_random: [u8; 32],
        server_key: p256::PublicKey,
    ) -> Result<(), MpcTlsError> {
        self.prf.set_server_random(server_random)?;
        self.ke.set_server_key(server_key)?;
        self.ke.compute_shares(&mut self.ctx).await?;

        let mut vm = self
            .vm
            .try_lock()
            .map_err(|_| MpcTlsError::other("VM lock is held"))?;

        self.ke.assign(&mut *vm)?;
        flush_prf(&mut self.prf, &mut *vm, &mut self.ctx).await?;

        self.ke.finalize().await?;
        self.record_layer.setup(&mut self.ctx).await?;

        Ok(())
    }

    /// Computes the client Finished verify data from the handshake hash.
    pub(crate) async fn compute_cf_vd(&mut self, hash: [u8; 32]) -> Result<[u8; 12], MpcTlsError> {
        let mut vm = self
            .vm
            .try_lock()
            .map_err(|_| MpcTlsError::other("VM lock is held"))?;

        self.prf.set_cf_hash(hash)?;
        flush_prf(&mut self.prf, &mut *vm, &mut self.ctx).await?;

        let vd = self
            .cf_vd_fut
            .as_mut()
            .ok_or_else(|| MpcTlsError::state("client finished verify data not allocated"))?
            .try_recv()
            .map_err(MpcTlsError::hs)?
            .ok_or_else(|| MpcTlsError::hs("cf_vd is not decoded"))?;

        self.cf_vd = Some(vd);

        Ok(vd)
    }

    /// Computes the server Finished verify data from the handshake hash.
    pub(crate) async fn compute_sf_vd(&mut self, hash: [u8; 32]) -> Result<[u8; 12], MpcTlsError> {
        let mut vm = self
            .vm
            .try_lock()
            .map_err(|_| MpcTlsError::other("VM lock is held"))?;

        self.prf.set_sf_hash(hash)?;
        flush_prf(&mut self.prf, &mut *vm, &mut self.ctx).await?;

        let vd = self
            .sf_vd_fut
            .as_mut()
            .ok_or_else(|| MpcTlsError::state("server finished verify data not allocated"))?
            .try_recv()
            .map_err(MpcTlsError::hs)?
            .ok_or_else(|| MpcTlsError::hs("sf_vd is not decoded"))?;

        self.sf_vd = Some(vd);

        Ok(vd)
    }

    /// Buffers an outgoing record for encryption.
    pub(crate) fn push_encrypt(
        &mut self,
        typ: tls_core::msgs::enums::ContentType,
        version: tls_core::msgs::enums::ProtocolVersion,
        len: usize,
        plaintext: Option<Vec<u8>>,
    ) -> Result<(), MpcTlsError> {
        self.record_layer.push_encrypt(typ, version, len, plaintext)
    }

    /// Buffers an incoming record for decryption.
    pub(crate) fn push_decrypt(
        &mut self,
        typ: tls_core::msgs::enums::ContentType,
        version: tls_core::msgs::enums::ProtocolVersion,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        tag: Vec<u8>,
    ) -> Result<(), MpcTlsError> {
        self.record_layer
            .push_decrypt(typ, version, explicit_nonce, ciphertext, tag)
    }

    /// Returns the next encrypted record, if available.
    pub(crate) fn next_encrypted(&mut self) -> Option<EncryptedRecord> {
        self.record_layer.next_encrypted()
    }

    /// Returns the next decrypted record, if available.
    pub(crate) fn next_decrypted(&mut self) -> Option<PlainRecord> {
        self.record_layer.next_decrypted()
    }

    /// Signals the record layer to start processing application data.
    pub(crate) fn start_traffic(&mut self) {
        self.record_layer.start_traffic();
    }

    /// Returns whether the record layer has buffered operations to flush.
    pub(crate) fn wants_flush(&self) -> bool {
        self.record_layer.wants_flush()
    }

    /// Returns whether the record layer has no buffered records.
    pub(crate) fn record_layer_is_empty(&self) -> bool {
        self.record_layer.is_empty()
    }

    /// Flushes the record layer, executing buffered encrypt/decrypt operations.
    pub(crate) async fn flush(&mut self, is_decrypting: bool) -> Result<(), MpcTlsError> {
        self.record_layer
            .flush(&mut self.ctx, self.vm.clone(), is_decrypting)
            .await
    }

    /// Commits to the record layer, returning the sent and received records.
    pub(crate) async fn commit(&mut self) -> Result<(Vec<Record>, Vec<Record>), MpcTlsError> {
        self.record_layer.commit(&mut self.ctx, self.vm.clone()).await
    }

    /// Verifies the Finished verify data in `transcript` against the values
    /// computed in MPC, and that both directions of the connection were closed
    /// properly.
    pub(crate) fn verify_transcript(&self, transcript: &TlsTranscript) -> Result<(), MpcTlsError> {
        let expected_cf_vd = self
            .cf_vd
            .ok_or_else(|| MpcTlsError::state("client finished verify data not computed"))?;
        let expected_sf_vd = self
            .sf_vd
            .ok_or_else(|| MpcTlsError::state("server finished verify data not computed"))?;

        let cf_vd = transcript
            .cf_vd()
            .expect("client finished verify data should be available");
        if cf_vd != expected_cf_vd {
            return Err(MpcTlsError::peer("client verify data is incorrect"));
        }

        let sf_vd = transcript
            .sf_vd()
            .expect("server finished verify data should be available");
        if sf_vd != expected_sf_vd {
            return Err(MpcTlsError::peer("server verify data is incorrect"));
        }

        check_close_notify(transcript.sent())?;
        check_close_notify(transcript.recv())?;

        Ok(())
    }

    /// Consumes the session after the connection is closed, returning the I/O
    /// context and the record layer (which retains the committed records).
    pub(crate) fn into_closed(self) -> (Context, RecordLayer) {
        (self.ctx, self.record_layer)
    }
}

/// Flushes the PRF, executing the VM until the PRF has no more work.
async fn flush_prf(
    prf: &mut Prf,
    vm: &mut (dyn VmTrait<Binary> + Send + Sync),
    ctx: &mut Context,
) -> Result<(), MpcTlsError> {
    while prf.wants_flush() {
        prf.flush(&mut *vm).map_err(MpcTlsError::hs)?;
        vm.execute_all(ctx).await.map_err(MpcTlsError::hs)?;
    }

    Ok(())
}

/// Splits an opaque AES-GCM record into its explicit nonce, ciphertext and tag.
#[allow(clippy::type_complexity)]
pub(crate) fn opaque_into_parts(
    mut msg: Vec<u8>,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), MpcTlsError> {
    if msg.len() < EXPLICIT_NONCE_LEN + TAG_LEN {
        return Err(MpcTlsError::record_layer("ciphertext record is too short"));
    }

    let tag = msg.split_off(msg.len() - TAG_LEN);
    let ciphertext = msg.split_off(EXPLICIT_NONCE_LEN);
    let explicit_nonce = msg;

    Ok((explicit_nonce, ciphertext, tag))
}

/// Verifies that, if the last record is an alert, it is a `close_notify`.
fn check_close_notify(records: &[Record]) -> Result<(), MpcTlsError> {
    let Some(last_record) = records.last() else {
        return Ok(());
    };

    match last_record.typ {
        ContentType::ApplicationData => {}
        ContentType::Alert => {
            let payload = last_record
                .plaintext
                .as_ref()
                .ok_or_else(|| MpcTlsError::peer("alert content was hidden from the follower"))?;

            let mut reader = Reader::init(payload);
            let alert = AlertMessagePayload::read(&mut reader)
                .ok_or_else(|| MpcTlsError::peer("alert message was malformed"))?;

            let AlertDescription::CloseNotify = alert.description else {
                return Err(MpcTlsError::peer(
                    "last record is an alert that is not close notify",
                ));
            };
        }
        typ => {
            return Err(MpcTlsError::peer(format!(
                "last record has unexpected record content type: {typ:?}",
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opaque_into_parts() {
        let msg = (0u8..32).collect::<Vec<_>>();
        let (nonce, ciphertext, tag) = opaque_into_parts(msg).unwrap();
        assert_eq!(nonce, (0..8).collect::<Vec<_>>());
        assert_eq!(ciphertext, (8..16).collect::<Vec<_>>());
        assert_eq!(tag, (16..32).collect::<Vec<_>>());
    }

    #[test]
    fn test_opaque_into_parts_rejects_short_record() {
        // A record shorter than nonce + tag must error, not panic.
        for len in 0..24 {
            assert!(opaque_into_parts(vec![0; len]).is_err());
        }
        // An empty ciphertext is the acceptance boundary.
        assert!(opaque_into_parts(vec![0; 24]).is_ok());
    }

    #[test]
    fn test_check_close_notify() {
        fn record(typ: ContentType, plaintext: Option<Vec<u8>>) -> Record {
            Record {
                seq: 0,
                typ,
                plaintext,
                explicit_nonce: Vec::new(),
                ciphertext: Vec::new(),
                tag: None,
            }
        }

        let close_notify = AlertMessagePayload {
            level: tls_core::msgs::enums::AlertLevel::Warning,
            description: AlertDescription::CloseNotify,
        };
        let mut payload = Vec::new();
        close_notify.encode(&mut payload);

        // No records, application data, or a trailing close_notify are fine.
        assert!(check_close_notify(&[]).is_ok());
        assert!(check_close_notify(&[record(ContentType::ApplicationData, None)]).is_ok());
        assert!(check_close_notify(&[record(ContentType::Alert, Some(payload))]).is_ok());

        // Hidden alert content, malformed alerts, other alerts and other
        // content types are rejected.
        assert!(check_close_notify(&[record(ContentType::Alert, None)]).is_err());
        assert!(check_close_notify(&[record(ContentType::Alert, Some(vec![0xff]))]).is_err());
        let unexpected = AlertMessagePayload {
            level: tls_core::msgs::enums::AlertLevel::Fatal,
            description: AlertDescription::HandshakeFailure,
        };
        let mut payload = Vec::new();
        unexpected.encode(&mut payload);
        assert!(check_close_notify(&[record(ContentType::Alert, Some(payload))]).is_err());
        assert!(check_close_notify(&[record(ContentType::Handshake, None)]).is_err());
    }
}
