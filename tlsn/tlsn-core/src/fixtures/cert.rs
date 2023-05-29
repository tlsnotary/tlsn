#[cfg(test)]
use std::time::{Duration, SystemTime};

use rstest::{fixture, rstest};
use tls_core::{
    anchors::{OwnedTrustAnchor, RootCertStore},
    dns::ServerName,
    key::{Certificate, PublicKey},
    msgs::{
        codec::Codec,
        enums::{NamedGroup, SignatureAlgorithm},
        handshake::{Random, ServerECDHParams},
    },
    verify::ServerCertVerifier,
};

pub struct TestData {
    // end-entity cert
    pub ee: Certificate,
    // intermediate cert
    pub inter: Certificate,
    // CA cert
    pub ca: Certificate,
    // client random
    pub cr: Random,
    // server random
    pub sr: Random,
    // server ephemeral P256 pubkey
    pub pubkey: PublicKey,
    // server signature over the key exchange parameters
    pub sig: Vec<u8>,
    // unix time when TLS handshake began
    pub time: u64,
    // algorithm used to create the sig
    pub sigalg: SignatureAlgorithm,
    // DNS name of the website
    pub dns_name: ServerName,
}

impl TestData {
    pub fn kx_params(&self) -> Vec<u8> {
        let mut params = Vec::new();
        let ecdh_params = ServerECDHParams::new(NamedGroup::secp256r1, &self.pubkey.key);
        ecdh_params.encode(&mut params);
        params
    }

    pub fn signature_msg(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&self.cr.0);
        msg.extend_from_slice(&self.sr.0);
        msg.extend_from_slice(&self.kx_params());
        msg
    }
}

// convert a hex string to bytes
fn from_hex(string: &[u8]) -> Vec<u8> {
    hex::decode(string.to_ascii_lowercase()).unwrap()
}

#[fixture]
pub fn cert_verifier() -> impl ServerCertVerifier {
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    tls_core::verify::WebPkiVerifier::new(root_store, None)
}

#[fixture]
pub fn tlsnotary() -> TestData {
    TestData {
        ee: Certificate(include_bytes!("testdata/key_exchange/tlsnotary.org/ee.der").to_vec()),
        inter: Certificate(
            include_bytes!("testdata/key_exchange/tlsnotary.org/inter.der").to_vec(),
        ),
        ca: Certificate(include_bytes!("testdata/key_exchange/tlsnotary.org/ca.der").to_vec()),
        cr: Random(
            from_hex(include_bytes!(
                "testdata/key_exchange/tlsnotary.org/client_random"
            ))
            .try_into()
            .unwrap(),
        ),
        sr: Random(
            from_hex(include_bytes!(
                "testdata/key_exchange/tlsnotary.org/server_random"
            ))
            .try_into()
            .unwrap(),
        ),
        pubkey: PublicKey::new(
            NamedGroup::secp256r1,
            &from_hex(include_bytes!("testdata/key_exchange/tlsnotary.org/pubkey")),
        ),
        sig: from_hex(include_bytes!(
            "testdata/key_exchange/tlsnotary.org/signature"
        )),
        time: 1671637529,
        sigalg: SignatureAlgorithm::RSA,
        dns_name: ServerName::try_from("tlsnotary.org").unwrap(),
    }
}

#[fixture]
pub fn appliedzkp() -> TestData {
    TestData {
        ee: Certificate(include_bytes!("testdata/key_exchange/appliedzkp.org/ee.der").to_vec()),
        inter: Certificate(
            include_bytes!("testdata/key_exchange/appliedzkp.org/inter.der").to_vec(),
        ),
        ca: Certificate(include_bytes!("testdata/key_exchange/appliedzkp.org/ca.der").to_vec()),
        cr: Random(
            from_hex(include_bytes!(
                "testdata/key_exchange/appliedzkp.org/client_random"
            ))
            .try_into()
            .unwrap(),
        ),
        sr: Random(
            from_hex(include_bytes!(
                "testdata/key_exchange/appliedzkp.org/server_random"
            ))
            .try_into()
            .unwrap(),
        ),
        pubkey: PublicKey::new(
            NamedGroup::secp256r1,
            &from_hex(include_bytes!(
                "testdata/key_exchange/appliedzkp.org/pubkey"
            )),
        ),
        sig: from_hex(include_bytes!(
            "testdata/key_exchange/appliedzkp.org/signature"
        )),
        time: 1671637529,
        sigalg: SignatureAlgorithm::ECDSA,
        dns_name: ServerName::try_from("appliedzkp.org").unwrap(),
    }
}

#[rstest]
#[case(tlsnotary())]
#[case(appliedzkp())]
/// Expect chain verification to succeed
fn test_verify_cert_chain_sucess_ca_implicit(
    cert_verifier: impl ServerCertVerifier,
    #[case] data: TestData,
) {
    assert!(cert_verifier
        .verify_server_cert(
            &data.ee,
            &[data.inter],
            &data.dns_name,
            &mut std::iter::empty(),
            &[],
            SystemTime::UNIX_EPOCH + Duration::from_secs(data.time),
        )
        .is_ok());
}

#[rstest]
#[case(tlsnotary())]
#[case(appliedzkp())]
/// Expect chain verification to succeed even when a trusted CA is provided among the intermediate
/// certs. webpki handles such cases properly.
fn test_verify_cert_chain_success_ca_explicit(
    cert_verifier: impl ServerCertVerifier,
    #[case] data: TestData,
) {
    assert!(cert_verifier
        .verify_server_cert(
            &data.ee,
            &[data.inter, data.ca],
            &data.dns_name,
            &mut std::iter::empty(),
            &[],
            SystemTime::UNIX_EPOCH + Duration::from_secs(data.time),
        )
        .is_ok());
}

#[rstest]
#[case(tlsnotary())]
#[case(appliedzkp())]
// Expect to fail since the end entity cert was not valid at the time
fn test_verify_cert_chain_fail_bad_time(
    cert_verifier: impl ServerCertVerifier,
    #[case] data: TestData,
) {
    // unix time when the cert chain was NOT valid
    let bad_time: u64 = 1571465711;

    let err = cert_verifier.verify_server_cert(
        &data.ee,
        &[data.inter],
        &data.dns_name,
        &mut std::iter::empty(),
        &[],
        SystemTime::UNIX_EPOCH + Duration::from_secs(bad_time),
    );

    assert!(matches!(
        err.unwrap_err(),
        tls_core::Error::InvalidCertificateData(_)
    ));
}

#[rstest]
#[case(tlsnotary())]
#[case(appliedzkp())]
// Expect to fail when no intermediate cert provided
fn test_verify_cert_chain_fail_no_interm_cert(
    cert_verifier: impl ServerCertVerifier,
    #[case] data: TestData,
) {
    let err = cert_verifier.verify_server_cert(
        &data.ee,
        &[],
        &data.dns_name,
        &mut std::iter::empty(),
        &[],
        SystemTime::UNIX_EPOCH + Duration::from_secs(data.time),
    );

    assert!(matches!(
        err.unwrap_err(),
        tls_core::Error::InvalidCertificateData(_)
    ));
}

#[rstest]
#[case(tlsnotary())]
#[case(appliedzkp())]
// Expect to fail when no intermediate cert provided even if a trusted CA cert is provided
fn test_verify_cert_chain_fail_no_interm_cert_with_ca_cert(
    cert_verifier: impl ServerCertVerifier,
    #[case] data: TestData,
) {
    let err = cert_verifier.verify_server_cert(
        &data.ee,
        &[data.ca],
        &data.dns_name,
        &mut std::iter::empty(),
        &[],
        SystemTime::UNIX_EPOCH + Duration::from_secs(data.time),
    );

    assert!(matches!(
        err.unwrap_err(),
        tls_core::Error::InvalidCertificateData(_)
    ));
}

#[rstest]
#[case(tlsnotary())]
#[case(appliedzkp())]
// Expect to fail because end-entity cert is wrong
fn test_verify_cert_chain_fail_bad_ee_cert(
    cert_verifier: impl ServerCertVerifier,
    #[case] data: TestData,
) {
    let ee: &[u8] = include_bytes!("testdata/key_exchange/unknown/ee.der");

    let err = cert_verifier.verify_server_cert(
        &Certificate(ee.to_vec()),
        &[data.inter],
        &data.dns_name,
        &mut std::iter::empty(),
        &[],
        SystemTime::UNIX_EPOCH + Duration::from_secs(data.time),
    );

    assert!(matches!(
        err.unwrap_err(),
        tls_core::Error::InvalidCertificateData(_)
    ));
}

// // Expect to succeed when key exchange params signed correctly with a cert
// #[rstest]
// #[case(tlsnotary())]
// #[case(appliedzkp())]
// fn test_verify_sig_ke_params_success(
//     cert_verifier: impl ServerCertVerifier,
//     #[case] data: TestData,
// ) {
//     let sig = ServerSignature::new(data.sigalg, data.sig);
//     let ephem_pubkey = crate::pubkey::PubKey::from_bytes(KeyType::P256, &data.pubkey).unwrap();
//     let ke_params = KEData::new(ephem_pubkey, data.cr, data.sr);

//     assert!(data
//         .ee
//         .verify_signature(&ke_params.to_bytes().unwrap(), &sig)
//         .is_ok());
// }

// // Expect sig verification to fail because client_random is wrong
// #[rstest]
// #[case(tlsnotary())]
// #[case(appliedzkp())]
// fn test_verify_sig_ke_params_fail_bad_client_random(
//     cert_verifier: impl ServerCertVerifier,
//     #[case] data: TestData,
// ) {
//     let sig = ServerSignature::new(data.sigalg, data.sig);
//     let ephem_pubkey = crate::pubkey::PubKey::from_bytes(KeyType::P256, &data.pubkey).unwrap();

//     let mut cr = data.cr;
//     // corrupt the last byte of client random
//     let last = cr[31];
//     let (corrupted, _) = last.overflowing_add(1);
//     cr[31] = corrupted;

//     let ke_params = KEData::new(ephem_pubkey, cr, data.sr);
//     let err = data
//         .ee
//         .verify_signature(&ke_params.to_bytes().unwrap(), &sig);

//     assert_eq!(
//         err.unwrap_err(),
//         EndEntityCertError::WebpkiError("InvalidSignatureForPublicKey".to_string())
//     );
// }

// // Expect sig verification to fail because the sig is wrong
// #[rstest]
// #[case(tlsnotary())]
// #[case(appliedzkp())]
// fn test_verify_sig_ke_params_fail_bad_sig(
//     cert_verifier: impl ServerCertVerifier,
//     #[case] data: TestData,
// ) {
//     let mut sig = data.sig.clone();
//     // corrupt the last byte of the signature
//     let last = sig.pop().unwrap();
//     let (corrupted, _) = last.overflowing_add(1);
//     sig.push(corrupted);

//     let sig = ServerSignature::new(data.sigalg, sig);
//     let ephem_pubkey = crate::pubkey::PubKey::from_bytes(KeyType::P256, &data.pubkey).unwrap();
//     let ke_params = KEData::new(ephem_pubkey, data.cr, data.sr);

//     let err = data
//         .ee
//         .verify_signature(&ke_params.to_bytes().unwrap(), &sig);

//     assert_eq!(
//         err.unwrap_err(),
//         EndEntityCertError::WebpkiError("InvalidSignatureForPublicKey".to_string())
//     );
// }

// // Expect to succeed for a valid dns name
// #[rstest]
// #[case(tlsnotary())]
// #[case(appliedzkp())]
// fn test_check_dns_name_present_in_cert_success(
//     cert_verifier: impl ServerCertVerifier,
//     #[case] data: TestData,
// ) {
//     assert!(data.ee.verify_is_valid_for_dns_name(&data.dns_name).is_ok());
// }

// // Expect to fail because the dns name is not in the cert
// #[rstest]
// #[case(tlsnotary())]
// #[case(appliedzkp())]
// fn test_check_dns_name_present_in_cert_fail_bad_host(
//     cert_verifier: impl ServerCertVerifier,
//     #[case] data: TestData,
// ) {
//     let bad_name = String::from("bad_name");

//     let err = data.ee.verify_is_valid_for_dns_name(&bad_name);

//     let _str = String::from("CertNotValidForName");
//     assert_eq!(
//         err.unwrap_err(),
//         EndEntityCertError::WebpkiError("CertNotValidForName".to_string())
//     );
// }

// // Expect to fail because the host name is not a valid DNS name
// #[rstest]
// #[case(tlsnotary())]
// #[case(appliedzkp())]
// fn test_check_dns_name_present_in_cert_fail_invalid_dns_name(
//     cert_verifier: impl ServerCertVerifier,
//     #[case] data: TestData,
// ) {
//     let host = String::from("tlsnotary.org%");

//     let err = data.ee.verify_is_valid_for_dns_name(&host);

//     assert_eq!(
//         err.unwrap_err(),
//         EndEntityCertError::WebpkiError("InvalidDnsNameError".to_string())
//     );
// }
