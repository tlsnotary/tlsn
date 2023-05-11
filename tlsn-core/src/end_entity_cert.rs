use crate::{
    cert::Cert,
    error::Error,
    handshake_data::{ServerSigAlg, ServerSignature},
};
use serde::{Deserialize, Serialize};
use webpki::EndEntityCert as webpki_EndEntityCert;
use webpki_roots::TLS_SERVER_ROOTS;

type SignatureAlgorithms = &'static [&'static webpki::SignatureAlgorithm];

/// When validating a certificate chain, we expect that certificates were signed
/// using any of the following algorithms:
static SUPPORTED_SIG_ALGS: SignatureAlgorithms = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::ED25519,
    &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
];

/// An x509 end-entity cerificate
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct EndEntityCert {
    // ASN.1 DER-encoded encoding of this certificate
    der: Vec<u8>,
}

impl EndEntityCert {
    pub fn new(der: Vec<u8>) -> Self {
        Self { der }
    }

    /// Wraps [webpki::EndEntityCert]'s `verify_is_valid_tls_server_cert`
    pub fn verify_is_valid_tls_server_cert(
        &self,
        intermediate_certs: &[Cert],
        time: u64,
    ) -> Result<(), Error> {
        let time = webpki::Time::from_seconds_since_unix_epoch(time);

        let cert = webpki_EndEntityCert::try_from(self.der.as_slice())
            .map_err(|e| Error::WebpkiError(e.to_string()))?;

        // convert a vec of `IntermCert` into a slice of slices
        let interm: Vec<Vec<u8>> = intermediate_certs.iter().map(|c| c.as_bytes()).collect();
        let interm: Vec<&[u8]> = interm.iter().map(|v| v.as_slice()).collect();
        let interm = interm.as_slice();

        cert.verify_is_valid_tls_server_cert(SUPPORTED_SIG_ALGS, &TLS_SERVER_ROOTS, interm, time)
            .map_err(|e| Error::WebpkiError(e.to_string()))
    }

    /// Wraps [webpki::EndEntityCert]'s `verify_signature`
    pub fn verify_signature(
        &self,
        msg: &[u8],
        server_signature: &ServerSignature,
    ) -> Result<(), Error> {
        let sigalg = match &server_signature.alg() {
            ServerSigAlg::RSA_PKCS1_2048_8192_SHA256 => &webpki::RSA_PKCS1_2048_8192_SHA256,
            ServerSigAlg::ECDSA_P256_SHA256 => &webpki::ECDSA_P256_SHA256,
            #[allow(unreachable_patterns)]
            _ => return Err(Error::UnknownSigningAlgorithmInKeyExchange),
        };

        let cert = webpki_EndEntityCert::try_from(self.der.as_slice())
            .map_err(|e| Error::WebpkiError(e.to_string()))?;

        cert.verify_signature(sigalg, msg, server_signature.sig())
            .map_err(|e| Error::WebpkiError(e.to_string()))
    }

    /// Wraps [webpki::EndEntityCert]'s `verify_is_valid_for_dns_name`
    pub fn verify_is_valid_for_dns_name(&self, dns_name: &str) -> Result<(), Error> {
        let dns_name = webpki::DnsNameRef::try_from_ascii_str(dns_name)
            .map_err(|e| Error::WebpkiError(e.to_string()))?;

        let cert = webpki_EndEntityCert::try_from(self.der.as_slice())
            .map_err(|e| Error::WebpkiError(e.to_string()))?;

        cert.verify_is_valid_for_dns_name(dns_name)
            .map_err(|e| Error::WebpkiError(e.to_string()))
    }
}

#[cfg(test)]
pub(crate) mod test {
    use rstest::{fixture, rstest};

    use crate::{pubkey::KeyType, KEParams};

    use super::*;

    pub struct TestData {
        // end-entity cert
        pub ee: EndEntityCert,
        // intermediate cert
        pub inter: Cert,
        // CA cert
        pub ca: Cert,
        // client random
        pub cr: [u8; 32],
        // server random
        pub sr: [u8; 32],
        // server ephemeral P256 pubkey
        pub pubkey: Vec<u8>,
        // server signature over the key exchange parameters
        pub sig: Vec<u8>,
        // unix time when TLS handshake began
        pub time: u64,
        // algorithm used to create the sig
        pub sigalg: ServerSigAlg,
        // DNS name of the website
        pub dns_name: String,
    }

    // convert a hex string to bytes
    fn from_hex(string: &[u8]) -> Vec<u8> {
        hex::decode(string.to_ascii_lowercase()).unwrap()
    }

    #[fixture]
    pub fn tlsnotary() -> TestData {
        TestData {
            ee: EndEntityCert::new(
                include_bytes!("testdata/key_exchange/tlsnotary.org/ee.der").to_vec(),
            ),
            inter: Cert::new(
                include_bytes!("testdata/key_exchange/tlsnotary.org/inter.der").to_vec(),
            ),
            ca: Cert::new(include_bytes!("testdata/key_exchange/tlsnotary.org/ca.der").to_vec()),
            cr: from_hex(include_bytes!(
                "testdata/key_exchange/tlsnotary.org/client_random"
            ))
            .try_into()
            .unwrap(),
            sr: from_hex(include_bytes!(
                "testdata/key_exchange/tlsnotary.org/server_random"
            ))
            .try_into()
            .unwrap(),
            pubkey: from_hex(include_bytes!("testdata/key_exchange/tlsnotary.org/pubkey")),
            sig: from_hex(include_bytes!(
                "testdata/key_exchange/tlsnotary.org/signature"
            )),
            time: 1671637529,
            sigalg: ServerSigAlg::RSA_PKCS1_2048_8192_SHA256,
            dns_name: "tlsnotary.org".to_string(),
        }
    }

    #[fixture]
    pub fn appliedzkp() -> TestData {
        TestData {
            ee: EndEntityCert::new(
                include_bytes!("testdata/key_exchange/appliedzkp.org/ee.der").to_vec(),
            ),
            inter: Cert::new(
                include_bytes!("testdata/key_exchange/appliedzkp.org/inter.der").to_vec(),
            ),
            ca: Cert::new(include_bytes!("testdata/key_exchange/appliedzkp.org/ca.der").to_vec()),
            cr: from_hex(include_bytes!(
                "testdata/key_exchange/appliedzkp.org/client_random"
            ))
            .try_into()
            .unwrap(),
            sr: from_hex(include_bytes!(
                "testdata/key_exchange/appliedzkp.org/server_random"
            ))
            .try_into()
            .unwrap(),
            pubkey: from_hex(include_bytes!(
                "testdata/key_exchange/appliedzkp.org/pubkey"
            )),
            sig: from_hex(include_bytes!(
                "testdata/key_exchange/appliedzkp.org/signature"
            )),
            time: 1671637529,
            sigalg: ServerSigAlg::ECDSA_P256_SHA256,
            dns_name: "appliedzkp.org".to_string(),
        }
    }

    #[rstest]
    #[case(tlsnotary())]
    #[case(appliedzkp())]
    /// Expect chain verification to succeed
    fn test_verify_cert_chain_sucess_ca_implicit(#[case] data: TestData) {
        assert!(data
            .ee
            .verify_is_valid_tls_server_cert(&[data.inter], data.time)
            .is_ok());
    }

    #[rstest]
    #[case(tlsnotary())]
    #[case(appliedzkp())]
    /// Expect chain verification to succeed even when a trusted CA is provided among the intermediate
    /// certs. webpki handles such cases properly.
    fn test_verify_cert_chain_success_ca_explicit(#[case] data: TestData) {
        assert!(data
            .ee
            .verify_is_valid_tls_server_cert(&[data.ca, data.inter], data.time)
            .is_ok());
    }

    #[rstest]
    #[case(tlsnotary())]
    #[case(appliedzkp())]
    // Expect to fail since the end entity cert was not valid at the time
    fn test_verify_cert_chain_fail_bad_time(#[case] data: TestData) {
        // unix time when the cert chain was NOT valid
        let bad_time: u64 = 1571465711;

        let err = data
            .ee
            .verify_is_valid_tls_server_cert(&[data.inter], bad_time);

        assert_eq!(
            err.unwrap_err(),
            Error::WebpkiError("CertNotValidYet".to_string())
        );
    }

    #[rstest]
    #[case(tlsnotary())]
    #[case(appliedzkp())]
    // Expect to fail when no intermediate cert provided
    fn test_verify_cert_chain_fail_no_interm_cert(#[case] data: TestData) {
        let err = data.ee.verify_is_valid_tls_server_cert(&[], data.time);

        assert_eq!(
            err.unwrap_err(),
            Error::WebpkiError("UnknownIssuer".to_string())
        );
    }

    #[rstest]
    #[case(tlsnotary())]
    #[case(appliedzkp())]
    // Expect to fail when no intermediate cert provided even if a trusted CA cert is provided
    fn test_verify_cert_chain_fail_no_interm_cert_with_ca_cert(#[case] data: TestData) {
        let err = data
            .ee
            .verify_is_valid_tls_server_cert(&[data.ca], data.time);

        assert_eq!(
            err.unwrap_err(),
            Error::WebpkiError("UnknownIssuer".to_string())
        );
    }

    #[rstest]
    #[case(tlsnotary())]
    #[case(appliedzkp())]
    // Expect to fail because end-entity cert is wrong
    fn test_verify_cert_chain_fail_bad_ee_cert(#[case] data: TestData) {
        let ee: &[u8] = include_bytes!("testdata/key_exchange/unknown/ee.der");

        let err = EndEntityCert::new(ee.to_vec())
            .verify_is_valid_tls_server_cert(&[data.inter], data.time);

        assert_eq!(
            err.unwrap_err(),
            Error::WebpkiError("UnknownIssuer".to_string())
        );
    }

    #[test]
    // Expect to fail when untrusted root cert was provided, even though the cert chain
    // is valid
    fn test_verify_cert_chain_fail_unknown_root() {
        // locally generated valid chain with an unknown CA:
        let ee =
            EndEntityCert::new(include_bytes!("testdata/key_exchange/unknown/ee.der").to_vec());
        let ca = Cert::new(include_bytes!("testdata/key_exchange/unknown/ca.der").to_vec());

        // unix time when the end-entity cert was valid
        let time: u64 = 1671637529;

        let err = ee.verify_is_valid_tls_server_cert(&[ca], time);

        assert_eq!(
            err.unwrap_err(),
            Error::WebpkiError("UnknownIssuer".to_string())
        );
    }

    // Expect to succeed when key exchange params signed correctly with a cert
    #[rstest]
    #[case(tlsnotary())]
    #[case(appliedzkp())]
    fn test_verify_sig_ke_params_success(#[case] data: TestData) {
        let sig = ServerSignature::new(data.sigalg, data.sig);
        let ephem_pubkey = crate::pubkey::PubKey::from_bytes(KeyType::P256, &data.pubkey).unwrap();
        let ke_params = KEParams::new(ephem_pubkey, data.cr, data.sr);

        assert!(data
            .ee
            .verify_signature(&ke_params.to_bytes().unwrap(), &sig)
            .is_ok());
    }

    // Expect sig verification to fail because client_random is wrong
    #[rstest]
    #[case(tlsnotary())]
    #[case(appliedzkp())]
    fn test_verify_sig_ke_params_fail_bad_client_random(#[case] data: TestData) {
        let sig = ServerSignature::new(data.sigalg, data.sig);
        let ephem_pubkey = crate::pubkey::PubKey::from_bytes(KeyType::P256, &data.pubkey).unwrap();

        let mut cr = data.cr.clone();
        // corrupt the last byte of client random
        let last = cr[31];
        let (corrupted, _) = last.overflowing_add(1);
        cr[31] = corrupted;

        let ke_params = KEParams::new(ephem_pubkey, cr, data.sr);
        let err = data
            .ee
            .verify_signature(&ke_params.to_bytes().unwrap(), &sig);

        assert_eq!(
            err.unwrap_err(),
            Error::WebpkiError("InvalidSignatureForPublicKey".to_string())
        );
    }

    // Expect sig verification to fail because the sig is wrong
    #[rstest]
    #[case(tlsnotary())]
    #[case(appliedzkp())]
    fn test_verify_sig_ke_params_fail_bad_sig(#[case] data: TestData) {
        let mut sig = data.sig.clone();
        // corrupt the last byte of the signature
        let last = sig.pop().unwrap();
        let (corrupted, _) = last.overflowing_add(1);
        sig.push(corrupted);

        let sig = ServerSignature::new(data.sigalg, sig);
        let ephem_pubkey = crate::pubkey::PubKey::from_bytes(KeyType::P256, &data.pubkey).unwrap();
        let ke_params = KEParams::new(ephem_pubkey, data.cr, data.sr);

        let err = data
            .ee
            .verify_signature(&ke_params.to_bytes().unwrap(), &sig);

        assert_eq!(
            err.unwrap_err(),
            Error::WebpkiError("InvalidSignatureForPublicKey".to_string())
        );
    }

    // Expect to succeed for a valid dns name
    #[rstest]
    #[case(tlsnotary())]
    #[case(appliedzkp())]
    fn test_check_dns_name_present_in_cert_success(#[case] data: TestData) {
        assert!(data.ee.verify_is_valid_for_dns_name(&data.dns_name).is_ok());
    }

    // Expect to fail because the dns name is not in the cert
    #[rstest]
    #[case(tlsnotary())]
    #[case(appliedzkp())]
    fn test_check_dns_name_present_in_cert_fail_bad_host(#[case] data: TestData) {
        let bad_name = String::from("bad_name");

        let err = data.ee.verify_is_valid_for_dns_name(&bad_name);

        let _str = String::from("CertNotValidForName");
        assert_eq!(
            err.unwrap_err(),
            Error::WebpkiError("CertNotValidForName".to_string())
        );
    }

    // Expect to fail because the host name is not a valid DNS name
    #[rstest]
    #[case(tlsnotary())]
    #[case(appliedzkp())]
    fn test_check_dns_name_present_in_cert_fail_invalid_dns_name(#[case] data: TestData) {
        let host = String::from("tlsnotary.org%");

        let err = data.ee.verify_is_valid_for_dns_name(&host);

        assert_eq!(
            err.unwrap_err(),
            Error::WebpkiError("InvalidDnsNameError".to_string())
        );
    }
}
