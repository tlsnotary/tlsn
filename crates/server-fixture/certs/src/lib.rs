/// A certificate authority certificate fixture.
pub static CA_CERT_DER: &[u8] = include_bytes!("tls/root_ca_cert.der");
/// A server certificate (domain=test-server.io) fixture.
pub static SERVER_CERT_DER: &[u8] = include_bytes!("tls/test_server_cert.der");
/// A server private key fixture.
pub static SERVER_KEY_DER: &[u8] = include_bytes!("tls/test_server_private_key.der");
/// The domain name bound to the server certificate.
pub static SERVER_DOMAIN: &str = "test-server.io";
