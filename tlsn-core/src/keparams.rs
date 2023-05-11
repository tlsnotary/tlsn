use serde::{Deserialize, Serialize};

use crate::{error::Error, pubkey::PubKey};

/// Key exchange-related data that will be signed to create `signed_params`
/// as per TLS 1.2 spec https://www.ietf.org/rfc/rfc5246.html#page-52
#[derive(Serialize, Deserialize, Clone)]
pub struct KEData {
    ephem_pubkey: PubKey,
    client_random: [u8; 32],
    server_random: [u8; 32],
}

impl KEData {
    pub fn new(ephem_pubkey: PubKey, client_random: [u8; 32], server_random: [u8; 32]) -> Self {
        Self {
            ephem_pubkey,
            client_random,
            server_random,
        }
    }

    /// Returns serialized bytes that were signed by the server to generate the signature called
    /// `signed_params` in the TLS 1.2 spec
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        // curve constant from the TLS spec
        let curve_const = match &self.ephem_pubkey {
            PubKey::P256(_) => [0x00, 0x17],
        };

        // type of the public key from the TLS spec: 0x03 = "named_curve"
        let pubkey_type = [0x03];
        let pubkey_bytes = self.ephem_pubkey.to_bytes();

        Ok([
            self.client_random.as_slice(),
            self.server_random.as_slice(),
            &pubkey_type,
            &curve_const,
            &[pubkey_bytes.len() as u8], // pubkey length
            &pubkey_bytes,               // pubkey
        ]
        .concat())
    }

    pub fn ephem_pubkey(&self) -> &PubKey {
        &self.ephem_pubkey
    }
}
