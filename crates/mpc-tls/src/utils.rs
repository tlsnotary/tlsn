use tls_core::msgs::{
    alert::AlertMessagePayload,
    codec::{Codec, Reader},
    enums::AlertDescription,
};
use tlsn_core::transcript::{ContentType, Record};

use crate::MpcTlsError;

/// Split an opaque message into its constituent parts.
///
/// Returns the explicit nonce, ciphertext, and tag, respectively.
#[allow(clippy::type_complexity)]
pub(crate) fn opaque_into_parts(
    mut msg: Vec<u8>,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), MpcTlsError> {
    let tag = msg.split_off(msg.len() - 16);
    let ciphertext = msg.split_off(8);
    let explicit_nonce = msg;

    if explicit_nonce.len() != 8 {
        return Err(MpcTlsError::other("explicit nonce length is not 8"));
    }

    Ok((explicit_nonce, ciphertext, tag))
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
