use crate::handshake::error::Error;
use tracing::warn;
use tls_core::msgs::{
    enums::{ContentType, HandshakeType},
    message::MessagePayload,
};

/// For a Message $m, and a HandshakePayload enum member $payload_type,
/// return Ok(payload) if $m is both a handshake message and one that
/// has the given $payload_type.  If not, return Err(crate::handshake::Error) quoting
/// $handshake_type as the expected handshake type.
macro_rules! require_handshake_msg(
  ( $m:expr_2021, $handshake_type:path, $payload_type:path ) => (
    match &$m.payload {
        MessagePayload::Handshake(::tls_core::msgs::handshake::HandshakeMessagePayload {
            payload: $payload_type(hm),
            ..
        }) => Ok(hm),
        payload => Err($crate::handshake::check::inappropriate_handshake_message(
            payload,
            &[::tls_core::msgs::enums::ContentType::Handshake],
            &[$handshake_type]))
    }
  )
);

/// Like require_handshake_msg, but moves the payload out of $m.
macro_rules! require_handshake_msg_move(
  ( $m:expr_2021, $handshake_type:path, $payload_type:path ) => (
    match $m.payload {
        MessagePayload::Handshake(::tls_core::msgs::handshake::HandshakeMessagePayload {
            payload: $payload_type(hm),
            ..
        }) => Ok(hm),
        payload =>
            Err($crate::handshake::check::inappropriate_handshake_message(
                &payload,
                &[::tls_core::msgs::enums::ContentType::Handshake],
                &[$handshake_type]))
    }
  )
);

pub(crate) fn inappropriate_message(
    payload: &MessagePayload,
    content_types: &[ContentType],
) -> Error {
    warn!(
        "Received a {:?} message while expecting {:?}",
        payload.content_type(),
        content_types
    );
    Error::InappropriateMessage {
        expect_types: content_types.to_vec(),
        got_type: payload.content_type(),
    }
}

pub(crate) fn inappropriate_handshake_message(
    payload: &MessagePayload,
    content_types: &[ContentType],
    handshake_types: &[HandshakeType],
) -> Error {
    match payload {
        MessagePayload::Handshake(hsp) => {
            warn!(
                "Received a {:?} handshake message while expecting {:?}",
                hsp.typ, handshake_types
            );
            Error::InappropriateHandshakeMessage {
                expect_types: handshake_types.to_vec(),
                got_type: hsp.typ,
            }
        }
        payload => inappropriate_message(payload, content_types),
    }
}
