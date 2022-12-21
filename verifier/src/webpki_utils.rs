use super::tls_doc::{
    CertDER, EphemeralECPubkey, EphemeralECPubkeyType, SigKEParamsAlg, SignatureKeyExchangeParams,
};
use crate::Error;
use webpki::{self, DnsNameRef};
use webpki_roots;
use x509_parser::{certificate, prelude::FromDer};

type SignatureAlgorithms = &'static [&'static webpki::SignatureAlgorithm];

/// When validating the certificate chain, we expect that certificates were signed
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

/// Verifier that the x509 certificate `chain` was valid at the given `time`.
/// The end entity certificate must be the last in the `chain`.
pub fn verify_cert_chain(chain: &[CertDER], time: u64) -> Result<(), Error> {
    let time = webpki::Time::from_seconds_since_unix_epoch(time);
    let anchor = &webpki_roots::TLS_SERVER_ROOTS;

    let last_cert_der = match chain.last() {
        None => return Err(Error::EmptyCertificateChain),
        Some(last) => last.as_slice(),
    };

    // Parse the DER into x509. Since webpki doesn't expose the parser,
    // we use x509-parser instead
    let (_, x509) = certificate::X509Certificate::from_der(last_cert_der)
        .map_err(|e| Error::X509ParserError(e.to_string()))?;

    // the end entity must not be a certificate authority
    if x509.is_ca() {
        return Err(Error::EndEntityIsCA);
    }

    // parse the der again with webpki
    let cert = webpki::EndEntityCert::try_from(last_cert_der)
        .map_err(|e| Error::WebpkiError(e.to_string()))?;

    // Separate intermediate certificates (all certs except for the last one which is the end
    // entity cert). It is ok to keep the root cert among the interm certs because webpki will
    // handle such cases properly.
    let interm = (0..chain.len() - 1)
        .map(|i| chain[i].as_slice())
        .collect::<Vec<_>>();

    cert.verify_is_valid_tls_server_cert(SUPPORTED_SIG_ALGS, anchor, interm.as_slice(), time)
        .map_err(|e| Error::WebpkiError(e.to_string()))?;

    Ok(())
}

/// Verifies the signature over the TLS key exchange parameters
pub fn verify_sig_ke_params(
    // certificate which signed the key exchange parameters
    cert: &CertDER,
    sig_ke_params: &SignatureKeyExchangeParams,
    // the following three are the parameters that were signed
    ephem_pubkey: &EphemeralECPubkey,
    client_random: &[u8],
    server_random: &[u8],
) -> Result<(), Error> {
    let cert = webpki::EndEntityCert::try_from(cert.as_slice())
        .map_err(|e| Error::WebpkiError(e.to_string()))?;

    // curve constant from the TLS spec
    let curve_const = match &ephem_pubkey.typ {
        EphemeralECPubkeyType::p256 => [0x00, 0x17],
        _ => return Err(Error::UnknownCurveInKeyExchange),
    };

    // message that was signed
    let msg = [
        client_random,
        server_random,
        &[0x03], // type of the public key 0x03 = named_curve
        &curve_const,
        &[ephem_pubkey.pubkey.len() as u8], // pubkey length
        &ephem_pubkey.pubkey,               // pubkey
    ]
    .concat();

    // we can't use [webpki::SignatureAlgorithm] in [SignatureKeyExchangeParams::alg]
    // because it is not Clone. Instead we match:
    let sigalg = match &sig_ke_params.alg {
        SigKEParamsAlg::RSA_PKCS1_2048_8192_SHA256 => &webpki::RSA_PKCS1_2048_8192_SHA256,
        SigKEParamsAlg::ECDSA_P256_SHA256 => &webpki::ECDSA_P256_SHA256,
        _ => return Err(Error::UnknownSigningAlgorithmInKeyExchange),
    };

    cert.verify_signature(sigalg, &msg, &sig_ke_params.sig)
        .map_err(|e| Error::WebpkiError(e.to_string()))?;

    Ok(())
}

// check that the hostname is present in the cert
pub fn check_hostname_present_in_cert(cert: &CertDER, hostname: String) -> bool {
    let cert = webpki::EndEntityCert::try_from(cert.as_slice()).unwrap();
    let dns_name = webpki::DnsNameRef::try_from_ascii_str(hostname.as_str()).unwrap();
    cert.verify_is_valid_for_dns_name(dns_name).is_ok()
}

// return the leaf certificate from the chain (the last one)
pub fn extract_leaf_cert(chain: &Vec<CertDER>) -> CertDER {
    chain.last().unwrap().clone()
}

#[cfg(test)]
mod test {
    use crate::tls_doc::*;

    use super::*;

    /// end entity cert
    static EE: &[u8] = include_bytes!("testdata/tlsnotary.org/ee.der");
    // intermediate cert
    static INTER: &[u8] = include_bytes!("testdata/tlsnotary.org/inter.der");
    // certificate authority cert
    static CA: &[u8] = include_bytes!("testdata/tlsnotary.org/ca.der");
    // unix time when the cert chain was valid
    static TIME: u64 = 1671637529;
    // unix time when the cert chain was NOT valid
    static BADTIME: u64 = 1571465711;

    // Key exchange-related data for an RSA certificate. Generated with openssl
    // (see testdata/key_exchange/README for details)
    static RSA_CERT: &[u8] = include_bytes!("testdata/key_exchange/rsa/cert_rsa.der");
    static RSA_CR: &[u8] = include_bytes!("testdata/key_exchange/rsa/client_random");
    static RSA_SR: &[u8] = include_bytes!("testdata/key_exchange/rsa/server_random");
    static RSA_EPHEM_PUBKEY: &[u8] = include_bytes!("testdata/key_exchange/rsa/pubkey");
    static RSA_SIG: &[u8] = include_bytes!("testdata/key_exchange/rsa/signature");

    // Key exchange-related data for an ECDSA certificate. Generated with openssl
    // (see testdata/key_exchange/README for details)
    static ECDSA_CERT: &[u8] = include_bytes!("testdata/key_exchange/ecdsa/cert_ecdsa.der");
    static ECDSA_CR: &[u8] = include_bytes!("testdata/key_exchange/ecdsa/client_random");
    static ECDSA_SR: &[u8] = include_bytes!("testdata/key_exchange/ecdsa/server_random");
    static ECDSA_EPHEM_PUBKEY: &[u8] = include_bytes!("testdata/key_exchange/ecdsa/pubkey");
    static ECDSA_SIG: &[u8] = include_bytes!("testdata/key_exchange/ecdsa/signature");

    #[test]
    /// Expect to succeed when CA is explicitely provided
    fn test_verify_cert_chain_ca_explicit() {
        assert!(verify_cert_chain(&[CA.to_vec(), INTER.to_vec(), EE.to_vec()], TIME).is_ok());
    }

    #[test]
    /// Expect to succeed when CA is NOT explicitely provided. webpki will look
    /// it up among the trusted root certs.
    fn test_verify_cert_chain_ca_implicit() {
        assert!(verify_cert_chain(&[INTER.to_vec(), EE.to_vec()], TIME).is_ok());
    }

    #[test]
    // Expect to fail since the end entity cert was not valid at the time
    fn test_verify_cert_chain_bad_time() {
        let err = verify_cert_chain(&[CA.to_vec(), INTER.to_vec(), EE.to_vec()], BADTIME);
        let _str = String::from("CertNotValidYet");
        assert!(matches!(err, Err(Error::WebpkiError(_str))));
    }

    #[test]
    // Expect to fail when no end entity cert provided
    fn test_verify_cert_chain_no_leaf_cert() {
        let err = verify_cert_chain(&[CA.to_vec(), INTER.to_vec()], TIME);
        assert!(matches!(err, Err(Error::EndEntityIsCA)));
    }

    #[test]
    // Expect to fail when no intermediate cert provided
    fn test_verify_cert_chain_no_interm_cert() {
        let err = verify_cert_chain(&[CA.to_vec(), EE.to_vec()], TIME);
        let _str = String::from("UnknownIssuer");
        assert!(matches!(err, Err(Error::WebpkiError(_str))));
    }

    #[test]
    // Expect to fail when unknown root cert was provided, even though the cert chain
    // is valid
    fn test_verify_cert_chain_unknown_root() {
        // locally generated valid chain with an unknown CA:
        let ee: &[u8] = include_bytes!("testdata/unknown/ee.der");
        let ca: &[u8] = include_bytes!("testdata/unknown/ca.der");

        let err = verify_cert_chain(&[ca.to_vec(), ee.to_vec()], TIME);
        let _str = String::from("UnknownIssuer");
        assert!(matches!(err, Err(Error::WebpkiError(_str))));
    }

    // convert a hex string to bytes
    fn to_hex(string: &[u8]) -> Vec<u8> {
        hex::decode(string.to_ascii_lowercase()).unwrap()
    }

    // Expect to succeed when key exchange params signed correctly with an RSA cert
    #[test]
    fn test_verify_sig_ke_params_rsa() {
        let cr: &[u8] = &to_hex(RSA_CR);
        let sr: &[u8] = &to_hex(RSA_SR);
        let pubkey: &[u8] = &to_hex(RSA_EPHEM_PUBKEY);
        let sig: &[u8] = &to_hex(RSA_SIG);

        let sig = SignatureKeyExchangeParams {
            alg: SigKEParamsAlg::RSA_PKCS1_2048_8192_SHA256,
            sig: sig.to_vec(),
        };

        let pubkey = EphemeralECPubkey {
            pubkey: pubkey.to_vec(),
            typ: EphemeralECPubkeyType::p256,
        };

        assert!(verify_sig_ke_params(&RSA_CERT.to_vec(), &sig, &pubkey, cr, sr).is_ok());
    }

    // Expect to succeed when key exchange params signed correctly with an ECDSA cert
    #[test]
    fn test_verify_sig_ke_params_ecdsa() {
        let cr: &[u8] = &to_hex(ECDSA_CR);
        let sr: &[u8] = &to_hex(ECDSA_SR);
        let pubkey: &[u8] = &to_hex(ECDSA_EPHEM_PUBKEY);
        let sig: &[u8] = &to_hex(ECDSA_SIG);

        let sig = SignatureKeyExchangeParams {
            alg: SigKEParamsAlg::ECDSA_P256_SHA256,
            sig: sig.to_vec(),
        };

        let pubkey = EphemeralECPubkey {
            pubkey: pubkey.to_vec(),
            typ: EphemeralECPubkeyType::p256,
        };

        assert!(verify_sig_ke_params(&ECDSA_CERT.to_vec(), &sig, &pubkey, cr, sr).is_ok());
    }

    // Expect RSA sig verification to fail because client_random is wrong
    #[test]
    fn test_verify_sig_ke_params_rsa_bad_client_random() {
        let cr: &[u8] = &to_hex(RSA_CR);
        let sr: &[u8] = &to_hex(RSA_SR);
        let pubkey: &[u8] = &to_hex(RSA_EPHEM_PUBKEY);
        let sig: &[u8] = &to_hex(RSA_SIG);

        let sig = SignatureKeyExchangeParams {
            alg: SigKEParamsAlg::RSA_PKCS1_2048_8192_SHA256,
            sig: sig.to_vec(),
        };

        let pubkey = EphemeralECPubkey {
            pubkey: pubkey.to_vec(),
            typ: EphemeralECPubkeyType::p256,
        };

        let mut cr = cr.to_vec();
        // corrupt the last byte of client random
        let last = cr.pop().unwrap();
        let (corrupted, _) = last.overflowing_add(1);
        cr.push(corrupted);

        let err = verify_sig_ke_params(&RSA_CERT.to_vec(), &sig, &pubkey, &cr, sr);

        let _str = String::from("InvalidSignatureForPublicKey");
        assert!(matches!(err, Err(Error::WebpkiError(_str))));
    }

    // Expect ECDSA sig verification to fail because the sig is wrong
    #[test]
    fn test_verify_sig_ke_params_ecdsa_bad_sig() {
        let cr: &[u8] = &to_hex(ECDSA_CR);
        let sr: &[u8] = &to_hex(ECDSA_SR);
        let pubkey: &[u8] = &to_hex(ECDSA_EPHEM_PUBKEY);
        let sig: &[u8] = &to_hex(ECDSA_SIG);

        let mut sig = sig.to_vec();
        // corrupt the last byte of the signature
        let last = sig.pop().unwrap();
        let (corrupted, _) = last.overflowing_add(1);
        sig.push(corrupted);

        let sig = SignatureKeyExchangeParams {
            alg: SigKEParamsAlg::ECDSA_P256_SHA256,
            sig: sig.to_vec(),
        };

        let pubkey = EphemeralECPubkey {
            pubkey: pubkey.to_vec(),
            typ: EphemeralECPubkeyType::p256,
        };

        let err = verify_sig_ke_params(&ECDSA_CERT.to_vec(), &sig, &pubkey, cr, sr);
        let _str = String::from("InvalidSignatureForPublicKey");
        assert!(matches!(err, Err(Error::WebpkiError(_str))));
    }
}
