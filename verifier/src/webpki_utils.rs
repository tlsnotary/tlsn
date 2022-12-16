use super::tls_doc::{CertDER, EphemeralECPubkey, SignatureKeyExchangeParams};
use webpki::{self, DnsNameRef};
use webpki_roots;

type SignatureAlgorithms = &'static [&'static webpki::SignatureAlgorithm];

/// Which signature verification mechanisms we support.  No particular
/// order.
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

// check that cert chain was valid at the time when notarization was performed
pub fn check_tls_cert_chain(chain: &Vec<CertDER>, time: u64) -> bool {
    let time = webpki::Time::from_seconds_since_unix_epoch(time);
    let anchor = &webpki_roots::TLS_SERVER_ROOTS;
    let cert = webpki::EndEntityCert::try_from(chain.last().unwrap().as_slice()).unwrap();

    // extract intermediate certificates (all certs wxcept for the last one which is the leaf
    // cert)
    // TODO: how does webpki handle when there's a root cert among the interm certs?
    let interm = (0..chain.len() - 1)
        .map(|i| chain[i].as_slice())
        .collect::<Vec<_>>();

    let res =
        cert.verify_is_valid_tls_server_cert(SUPPORTED_SIG_ALGS, &anchor, interm.as_slice(), time);
    res.is_ok()
}

// check sig over key exchange parameters
pub fn check_sig_ke_params(
    cert: &CertDER,
    sig_ke_params: &SignatureKeyExchangeParams,
    ephem_pubkey: &EphemeralECPubkey,
    client_random: &Vec<u8>,
    server_random: &Vec<u8>,
) -> bool {
    let cert = webpki::EndEntityCert::try_from(cert.as_slice()).unwrap();

    // curve constant from the TLS spec
    let curve_const = match &ephem_pubkey.typ {
        p256 => [0x00, 0x17],
        _ => panic!(),
    };

    // data to be signed
    let mut tbs = client_random.clone();
    tbs.append(&mut server_random.clone());
    // type of the public key 0x03 = named_curve
    tbs.append(&mut [0x03].to_vec());
    tbs.append(&mut curve_const.to_vec());
    // pubkey length
    tbs.append(&mut [ephem_pubkey.pubkey.len() as u8].to_vec());
    // pubkey
    tbs.append(&mut ephem_pubkey.pubkey.to_vec());

    let sigalg = match &sig_ke_params.typ {
        rsa_pkcs1_sha256 => &webpki::RSA_PKCS1_2048_8192_SHA256,
        _ => panic!(),
    };
    let res = cert.verify_signature(sigalg, &tbs, &sig_ke_params.sig);
    res.is_ok()
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
