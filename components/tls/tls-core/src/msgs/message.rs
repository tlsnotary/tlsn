use crate::{
    error::Error,
    msgs::{
        alert::AlertMessagePayload,
        base::Payload,
        ccs::ChangeCipherSpecPayload,
        codec::{Codec, Reader},
        enums::{AlertDescription, AlertLevel, ContentType, HandshakeType, ProtocolVersion},
        handshake::HandshakeMessagePayload,
    },
};

use std::convert::TryFrom;

#[derive(Debug)]
pub enum MessagePayload {
    Alert(AlertMessagePayload),
    Handshake(HandshakeMessagePayload),
    ChangeCipherSpec(ChangeCipherSpecPayload),
    ApplicationData(Payload),
}

impl MessagePayload {
    pub fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            Self::Alert(ref x) => x.encode(bytes),
            Self::Handshake(ref x) => x.encode(bytes),
            Self::ChangeCipherSpec(ref x) => x.encode(bytes),
            Self::ApplicationData(ref x) => x.encode(bytes),
        }
    }

    pub fn new(typ: ContentType, vers: ProtocolVersion, payload: Payload) -> Result<Self, Error> {
        let mut r = Reader::init(&payload.0);
        let parsed = match typ {
            ContentType::ApplicationData => return Ok(Self::ApplicationData(payload)),
            ContentType::Alert => AlertMessagePayload::read(&mut r).map(MessagePayload::Alert),
            ContentType::Handshake => {
                HandshakeMessagePayload::read_version(&mut r, vers).map(MessagePayload::Handshake)
            }
            ContentType::ChangeCipherSpec => {
                ChangeCipherSpecPayload::read(&mut r).map(MessagePayload::ChangeCipherSpec)
            }
            _ => None,
        };

        parsed
            .filter(|_| !r.any_left())
            .ok_or(Error::CorruptMessagePayload(typ))
    }

    pub fn content_type(&self) -> ContentType {
        match self {
            Self::Alert(_) => ContentType::Alert,
            Self::Handshake(_) => ContentType::Handshake,
            Self::ChangeCipherSpec(_) => ContentType::ChangeCipherSpec,
            Self::ApplicationData(_) => ContentType::ApplicationData,
        }
    }
}

/// A TLS frame, named TLSPlaintext in the standard.
///
/// This type owns all memory for its interior parts. It is used to read/write from/to I/O
/// buffers as well as for fragmenting, joining and encryption/decryption. It can be converted
/// into a `Message` by decoding the payload.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OpaqueMessage {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: Payload,
}

impl OpaqueMessage {
    /// `MessageError` allows callers to distinguish between valid prefixes (might
    /// become valid if we read more data) and invalid data.
    pub fn read(r: &mut Reader) -> Result<Self, MessageError> {
        let typ = ContentType::read(r).ok_or(MessageError::TooShortForHeader)?;
        let version = ProtocolVersion::read(r).ok_or(MessageError::TooShortForHeader)?;
        let len = u16::read(r).ok_or(MessageError::TooShortForHeader)?;

        // Reject undersize messages
        //  implemented per section 5.1 of RFC8446 (TLSv1.3)
        //              per section 6.2.1 of RFC5246 (TLSv1.2)
        if typ != ContentType::ApplicationData && len == 0 {
            return Err(MessageError::IllegalLength);
        }

        // Reject oversize messages
        if len >= Self::MAX_PAYLOAD {
            return Err(MessageError::IllegalLength);
        }

        // Don't accept any new content-types.
        if let ContentType::Unknown(_) = typ {
            return Err(MessageError::IllegalContentType);
        }

        // Accept only versions 0x03XX for any XX.
        match version {
            ProtocolVersion::Unknown(ref v) if (v & 0xff00) != 0x0300 => {
                return Err(MessageError::IllegalProtocolVersion);
            }
            _ => {}
        };

        let mut sub = r.sub(len as usize).ok_or(MessageError::TooShortForLength)?;
        let payload = Payload::read(&mut sub);

        Ok(Self {
            typ,
            version,
            payload,
        })
    }

    pub fn encode(self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.typ.encode(&mut buf);
        self.version.encode(&mut buf);
        (self.payload.0.len() as u16).encode(&mut buf);
        self.payload.encode(&mut buf);
        buf
    }

    /// Force conversion into a plaintext message.
    ///
    /// This should only be used for messages that are known to be in plaintext. Otherwise, the
    /// `OpaqueMessage` should be decrypted into a `PlainMessage` using a `MessageDecrypter`.
    pub fn into_plain_message(self) -> PlainMessage {
        PlainMessage {
            version: self.version,
            typ: self.typ,
            payload: self.payload,
        }
    }

    /// This is the maximum on-the-wire size of a TLSCiphertext.
    /// That's 2^14 payload bytes, a header, and a 2KB allowance
    /// for ciphertext overheads.
    const MAX_PAYLOAD: u16 = 16384 + 2048;

    /// Content type, version and size.
    const HEADER_SIZE: u16 = 1 + 2 + 2;

    /// Maximum on-wire message size.
    pub const MAX_WIRE_SIZE: usize = (Self::MAX_PAYLOAD + Self::HEADER_SIZE) as usize;
}

impl From<Message> for PlainMessage {
    fn from(msg: Message) -> Self {
        let typ = msg.payload.content_type();
        let payload = match msg.payload {
            MessagePayload::ApplicationData(payload) => payload,
            _ => {
                let mut buf = Vec::new();
                msg.payload.encode(&mut buf);
                Payload(buf)
            }
        };

        Self {
            typ,
            version: msg.version,
            payload,
        }
    }
}

/// A decrypted TLS frame
///
/// This type owns all memory for its interior parts. It can be decrypted from an OpaqueMessage
/// or encrypted into an OpaqueMessage, and it is also used for joining and fragmenting.
#[derive(Clone, Debug)]
pub struct PlainMessage {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: Payload,
}

impl PlainMessage {
    pub fn into_unencrypted_opaque(self) -> OpaqueMessage {
        OpaqueMessage {
            version: self.version,
            typ: self.typ,
            payload: self.payload,
        }
    }

    pub fn borrow(&self) -> BorrowedPlainMessage<'_> {
        BorrowedPlainMessage {
            version: self.version,
            typ: self.typ,
            payload: &self.payload.0,
        }
    }
}

/// A message with decoded payload
#[derive(Debug)]
pub struct Message {
    pub version: ProtocolVersion,
    pub payload: MessagePayload,
}

impl Message {
    pub fn is_handshake_type(&self, hstyp: HandshakeType) -> bool {
        // Bit of a layering violation, but OK.
        if let MessagePayload::Handshake(ref hsp) = self.payload {
            hsp.typ == hstyp
        } else {
            false
        }
    }

    pub fn build_alert(level: AlertLevel, desc: AlertDescription) -> Self {
        Self {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Alert(AlertMessagePayload {
                level,
                description: desc,
            }),
        }
    }

    pub fn build_key_update_notify() -> Self {
        Self {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::Handshake(HandshakeMessagePayload::build_key_update_notify()),
        }
    }
}

/// Parses a plaintext message into a well-typed [`Message`].
///
/// A [`PlainMessage`] must contain plaintext content. Encrypted content should be stored in an
/// [`OpaqueMessage`] and decrypted before being stored into a [`PlainMessage`].
impl TryFrom<PlainMessage> for Message {
    type Error = Error;

    fn try_from(plain: PlainMessage) -> Result<Self, Self::Error> {
        Ok(Self {
            version: plain.version,
            payload: MessagePayload::new(plain.typ, plain.version, plain.payload)?,
        })
    }
}

/// A TLS frame, named TLSPlaintext in the standard.
///
/// This type differs from `OpaqueMessage` because it borrows
/// its payload.  You can make a `OpaqueMessage` from an
/// `BorrowMessage`, but this involves a copy.
///
/// This type also cannot decode its internals and
/// cannot be read/encoded; only `OpaqueMessage` can do that.
pub struct BorrowedPlainMessage<'a> {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: &'a [u8],
}

#[derive(Debug)]
pub enum MessageError {
    TooShortForHeader,
    TooShortForLength,
    IllegalLength,
    IllegalContentType,
    IllegalProtocolVersion,
}
