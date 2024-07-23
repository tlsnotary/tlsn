use tls_core::{
    key::{Certificate, PublicKey},
    msgs::{
        codec::Codec,
        enums::{NamedGroup, SignatureScheme},
        handshake::{DigitallySignedStruct, Random, ServerECDHParams},
    },
};

use hex::FromHex;

/// Collects data needed for testing
pub struct TestData {
    /// end-entity cert
    pub ee: Certificate,
    /// intermediate cert
    pub inter: Certificate,
    /// CA cert
    pub ca: Certificate,
    /// client random
    pub cr: Random,
    /// server random
    pub sr: Random,
    /// server ephemeral P256 pubkey
    pub pubkey: PublicKey,
    /// server signature over the key exchange parameters
    pub sig: Vec<u8>,
    /// unix time when TLS handshake began
    pub time: u64,
    /// algorithm used to create the sig
    pub sig_scheme: SignatureScheme,
    /// DNS name of the website
    pub dns_name: String,
}

impl TestData {
    /// Returns the [ServerECDHParams] in encoded form
    pub fn kx_params(&self) -> Vec<u8> {
        let mut params = Vec::new();
        let ecdh_params = ServerECDHParams::new(NamedGroup::secp256r1, &self.pubkey.key);
        ecdh_params.encode(&mut params);
        params
    }

    /// Returns the [DigitallySignedStruct]
    pub fn dss(&self) -> DigitallySignedStruct {
        DigitallySignedStruct::new(self.sig_scheme, self.sig.clone())
    }

    /// Returns the client random + server random + kx params in encoded form
    pub fn signature_msg(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&self.cr.0);
        msg.extend_from_slice(&self.sr.0);
        msg.extend_from_slice(&self.kx_params());
        msg
    }
}

/// Returns test data for the tlsnotary.org website
pub fn tlsnotary() -> TestData {
    TestData {
        ee: Certificate(include_bytes!("testdata/key_exchange/tlsnotary.org/ee.der").to_vec()),
        inter: Certificate(
            include_bytes!("testdata/key_exchange/tlsnotary.org/inter.der").to_vec(),
        ),
        ca: Certificate(include_bytes!("testdata/key_exchange/tlsnotary.org/ca.der").to_vec()),
        cr: Random(
            <[u8; 32]>::from_hex(include_bytes!(
                "testdata/key_exchange/tlsnotary.org/client_random"
            ))
            .unwrap(),
        ),
        sr: Random(
            <[u8; 32]>::from_hex(include_bytes!(
                "testdata/key_exchange/tlsnotary.org/server_random"
            ))
            .unwrap(),
        ),
        pubkey: PublicKey::new(
            NamedGroup::secp256r1,
            &Vec::<u8>::from_hex(include_bytes!("testdata/key_exchange/tlsnotary.org/pubkey"))
                .unwrap(),
        ),
        sig: Vec::<u8>::from_hex(include_bytes!(
            "testdata/key_exchange/tlsnotary.org/signature"
        ))
        .unwrap(),
        time: 1671637529,
        sig_scheme: SignatureScheme::RSA_PKCS1_SHA256,
        dns_name: "tlsnotary.org".to_string(),
    }
}

/// Returns test data for the appliedzkp.org website
pub fn appliedzkp() -> TestData {
    TestData {
        ee: Certificate(include_bytes!("testdata/key_exchange/appliedzkp.org/ee.der").to_vec()),
        inter: Certificate(
            include_bytes!("testdata/key_exchange/appliedzkp.org/inter.der").to_vec(),
        ),
        ca: Certificate(include_bytes!("testdata/key_exchange/appliedzkp.org/ca.der").to_vec()),
        cr: Random(
            <[u8; 32]>::from_hex(include_bytes!(
                "testdata/key_exchange/appliedzkp.org/client_random"
            ))
            .unwrap(),
        ),
        sr: Random(
            <[u8; 32]>::from_hex(include_bytes!(
                "testdata/key_exchange/appliedzkp.org/server_random"
            ))
            .unwrap(),
        ),
        pubkey: PublicKey::new(
            NamedGroup::secp256r1,
            &Vec::<u8>::from_hex(include_bytes!(
                "testdata/key_exchange/appliedzkp.org/pubkey"
            ))
            .unwrap(),
        ),
        sig: Vec::<u8>::from_hex(include_bytes!(
            "testdata/key_exchange/appliedzkp.org/signature"
        ))
        .unwrap(),
        time: 1671637529,
        sig_scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
        dns_name: "appliedzkp.org".to_string(),
    }
}
