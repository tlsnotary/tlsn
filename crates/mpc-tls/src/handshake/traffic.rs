//! Online (post-handshake) message processing.
//!
//! Once the handshake completes the connection enters the online phase, where
//! the handshake state machine no longer applies. This module routes the TLS
//! messages that may legitimately arrive during application-data transfer.

use crate::{
    conn::Conn,
    handshake::{check::inappropriate_message, error::Error},
};
use tls_core::msgs::{
    enums::{AlertDescription, ContentType, HandshakeType},
    handshake::{HandshakeMessagePayload, HandshakePayload},
    message::{Message, MessagePayload},
};

/// Processes a fully-parsed TLS message received while the connection is in the
/// online (post-handshake) phase.
///
/// Alerts are handled by the caller before dispatch; this handles application
/// data, TLS 1.2 renegotiation rejection, and the TLS 1.3 post-handshake
/// messages (the latter dormant: the MPC backend never completes a TLS 1.3
/// handshake, so the connection never reaches this point under TLS 1.3).
pub(crate) async fn process_online(conn: &mut Conn, msg: Message) -> Result<(), Error> {
    // TLS 1.2 renegotiation requests are rejected outside the handshake. These
    // can occur at any time.
    if !conn.io.is_tls13() && msg.is_handshake_type(HandshakeType::HelloRequest) {
        conn.send_warning_alert(AlertDescription::NoRenegotiation)
            .await?;
        return Ok(());
    }

    match msg.payload {
        MessagePayload::ApplicationData(payload) => conn.io.take_received_plaintext(payload),
        MessagePayload::Handshake(HandshakeMessagePayload {
            payload: HandshakePayload::NewSessionTicketTLS13(ref nst),
            ..
        }) if conn.io.is_tls13() => {
            if nst.has_duplicate_extension() {
                conn.send_fatal_alert(AlertDescription::IllegalParameter)
                    .await?;
                return Err(Error::PeerMisbehavedError(
                    "peer sent duplicate NewSessionTicket extensions".into(),
                ));
            }
        }
        MessagePayload::Handshake(HandshakeMessagePayload {
            payload: HandshakePayload::KeyUpdate(_),
            ..
        }) if conn.io.is_tls13() => {
            // A key update must not be interleaved with a fragmented handshake
            // message, and the client does not support key updates.
            conn.check_aligned_handshake().await?;
            conn.send_fatal_alert(AlertDescription::InternalError)
                .await?;
            return Err(Error::General(
                "received unsupported key update request from peer".to_string(),
            ));
        }
        payload => {
            return Err(inappropriate_message(
                &payload,
                &[ContentType::ApplicationData],
            ));
        }
    }

    Ok(())
}
