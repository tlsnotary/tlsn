use std::{error::Error as StdError, fmt};

use crate::verify;

/// Encodes ways a client can know the expected name of the server.
///
/// This currently covers knowing the DNS name of the server, but
/// will be extended in the future to knowing the IP address of the
/// server, as well as supporting privacy-preserving names for the
/// server ("ECH").  For this reason this enum is `non_exhaustive`.
///
/// # Making one
///
/// If you have a DNS name as a `&str`, this type implements `TryFrom<&str>`,
/// so you can do:
///
/// ```
/// # use std::convert::{TryInto, TryFrom};
/// # use tls_core::dns::ServerName;
/// ServerName::try_from("example.com").expect("invalid DNS name");
///
/// // or, alternatively...
///
/// let x = "example.com".try_into().expect("invalid DNS name");
/// # let _: ServerName = x;
/// ```
#[non_exhaustive]
#[derive(Debug, PartialEq, Clone)]
pub enum ServerName {
    /// The server is identified by a DNS name.  The name
    /// is sent in the TLS Server Name Indication (SNI)
    /// extension.
    DnsName(verify::DnsName),
}

impl ServerName {
    /// Return the name that should go in the SNI extension.
    /// If [`None`] is returned, the SNI extension is not included
    /// in the handshake.
    pub fn for_sni(&self) -> Option<webpki::DnsNameRef> {
        match self {
            Self::DnsName(dns_name) => Some(dns_name.0.as_ref()),
        }
    }

    /// Return a prefix-free, unique encoding for the name.
    pub fn encode(&self) -> Vec<u8> {
        enum UniqueTypeCode {
            DnsName = 0x01,
        }

        let Self::DnsName(dns_name) = self;
        let bytes = dns_name.0.as_ref();

        let mut r = Vec::with_capacity(2 + bytes.as_ref().len());
        r.push(UniqueTypeCode::DnsName as u8);
        r.push(bytes.as_ref().len() as u8);
        r.extend_from_slice(bytes.as_ref());

        r
    }
}

/// Attempt to make a ServerName from a string by parsing
/// it as a DNS name.
impl TryFrom<&str> for ServerName {
    type Error = InvalidDnsNameError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match webpki::DnsNameRef::try_from_ascii_str(s) {
            Ok(dns) => Ok(Self::DnsName(verify::DnsName(dns.into()))),
            Err(webpki::InvalidDnsNameError) => Err(InvalidDnsNameError),
        }
    }
}

/// The provided input could not be parsed because
/// it is not a syntactically-valid DNS Name.
#[derive(Debug)]
pub struct InvalidDnsNameError;

impl fmt::Display for InvalidDnsNameError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid dns name")
    }
}

impl StdError for InvalidDnsNameError {}
