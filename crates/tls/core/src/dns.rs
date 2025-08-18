use std::{error::Error as StdError, fmt};

use rustls_pki_types as pki_types;

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
pub struct ServerName(pub(crate) pki_types::ServerName<'static>);

impl ServerName {
    /// Return the name that should go in the SNI extension.
    /// If [`None`] is returned, the SNI extension is not included
    /// in the handshake.
    pub fn for_sni(&self) -> Option<pki_types::DnsName<'static>> {
        match &self.0 {
            pki_types::ServerName::DnsName(dns_name) => Some(dns_name.clone()),
            _ => None,
        }
    }

    /// Return a prefix-free, unique encoding for the name.
    pub fn encode(&self) -> Vec<u8> {
        enum UniqueTypeCode {
            DnsName = 0x01,
        }

        let bytes: &[u8] = match &self.0 {
            pki_types::ServerName::DnsName(dns_name) => dns_name.as_ref().as_ref(),
            pki_types::ServerName::IpAddress(pki_types::IpAddr::V4(ip)) => ip.as_ref(),
            pki_types::ServerName::IpAddress(pki_types::IpAddr::V6(ip)) => ip.as_ref(),
            _ => unreachable!(),
        };

        let mut r = Vec::with_capacity(2 + bytes.len());
        r.push(UniqueTypeCode::DnsName as u8);
        r.push(bytes.len() as u8);
        r.extend_from_slice(bytes);

        r
    }
}

/// Attempt to make a ServerName from a string by parsing
/// it as a DNS name.
impl TryFrom<&str> for ServerName {
    type Error = InvalidDnsNameError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match pki_types::DnsName::try_from(s) {
            Ok(dns) => Ok(Self(pki_types::ServerName::DnsName(dns.to_owned()))),
            Err(_) => Err(InvalidDnsNameError),
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
