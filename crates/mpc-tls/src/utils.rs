use hmac_sha256::{Prf, PrfOutput};
use key_exchange::KeyExchange;
use mpz_common::Context;
use mpz_core::bitvec::BitVec;
use mpz_memory_core::{DecodeFutureTyped, MemoryExt, binary::Binary};
use mpz_vm_core::Vm;
use tls_core::msgs::{
    alert::AlertMessagePayload,
    codec::{Codec, Reader},
    enums::AlertDescription,
};
use tlsn_core::transcript::{ContentType, Record, TlsTranscript};

use crate::{Config, MpcTlsError, SessionKeys, record_layer::RecordLayer};

/// Length of the explicit nonce prefixing every AES-GCM record.
const EXPLICIT_NONCE_LEN: usize = 8;
/// Length of an AES-GCM authentication tag.
const TAG_LEN: usize = 16;

/// Split an opaque message into its constituent parts.
///
/// Returns the explicit nonce, ciphertext, and tag, respectively.
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

/// Allocates the MPC resources for a connection: the key exchange, the PRF
/// and the record layer.
///
/// Returns the session keys and the decode futures for the client and server
/// Finished verify data.
#[allow(clippy::type_complexity)]
pub(crate) fn alloc_session(
    vm: &mut (dyn Vm<Binary> + Send + Sync),
    config: &Config,
    ke: &mut (dyn KeyExchange + Send + Sync),
    prf: &mut Prf,
    record_layer: &mut RecordLayer,
) -> Result<
    (
        SessionKeys,
        DecodeFutureTyped<BitVec, [u8; 12]>,
        DecodeFutureTyped<BitVec, [u8; 12]>,
    ),
    MpcTlsError,
> {
    let pms = ke.alloc(&mut *vm)?;
    let PrfOutput { keys, cf_vd, sf_vd } = prf.alloc_pms(&mut *vm, pms)?;
    record_layer.set_keys(
        keys.client_write_key,
        keys.client_iv,
        keys.server_write_key,
        keys.server_iv,
    )?;

    let cf_vd = vm.decode(cf_vd).map_err(MpcTlsError::alloc)?;
    let sf_vd = vm.decode(sf_vd).map_err(MpcTlsError::alloc)?;

    let server_write_mac_key = record_layer.alloc(
        &mut *vm,
        config.max_sent_records,
        config.max_recv_records_online,
        config.max_sent,
        config.max_recv_online,
        config.max_recv,
    )?;

    let keys = SessionKeys {
        client_write_key: keys.client_write_key,
        client_write_iv: keys.client_iv,
        server_write_key: keys.server_write_key,
        server_write_iv: keys.server_iv,
        server_write_mac_key,
    };

    Ok((keys, cf_vd, sf_vd))
}

/// Flushes the PRF, executing the VM until the PRF has no more work.
pub(crate) async fn flush_prf(
    prf: &mut Prf,
    vm: &mut (dyn Vm<Binary> + Send + Sync),
    ctx: &mut Context,
) -> Result<(), MpcTlsError> {
    while prf.wants_flush() {
        prf.flush(&mut *vm).map_err(MpcTlsError::hs)?;
        vm.execute_all(ctx).await.map_err(MpcTlsError::hs)?;
    }

    Ok(())
}

/// Verifies the Finished verify data in `transcript` against the values
/// computed in MPC, and that both directions of the connection were closed
/// properly.
pub(crate) fn verify_transcript(
    transcript: &TlsTranscript,
    expected_cf_vd: [u8; 12],
    expected_sf_vd: [u8; 12],
) -> Result<(), MpcTlsError> {
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

pub(crate) fn check_close_notify(records: &[Record]) -> Result<(), MpcTlsError> {
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
