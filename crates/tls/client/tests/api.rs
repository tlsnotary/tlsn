//! Assorted public API tests.
#[cfg(feature = "tls12")]
use std::convert::TryInto;
use std::{
    cell::RefCell,
    convert::TryFrom,
    fmt,
    io::{self, IoSlice, Read, Write},
    mem,
    ops::{Deref, DerefMut},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use tls_client::{
    client::ResolvesClientCert, sign, CipherSuite, ClientConfig, ClientConnection, Error, KeyLog,
    ProtocolVersion, RustCryptoBackend, SignatureScheme, SupportedCipherSuite, ALL_CIPHER_SUITES,
};

use rustls::{
    server::{ClientHello, ResolvesServerCert},
    ServerConfig, ServerConnection,
};

mod common;
use crate::common::*;

async fn alpn_test_error(
    server_protos: Vec<Vec<u8>>,
    client_protos: Vec<Vec<u8>>,
    agreed: Option<&[u8]>,
    expected_error: Option<ErrorFromPeer>,
) {
    let mut server_config = make_server_config(KeyType::Rsa);
    server_config.alpn_protocols = server_protos;

    let server_config = Arc::new(server_config);

    for version in tls_client::ALL_VERSIONS {
        let mut client_config = make_client_config_with_versions(KeyType::Rsa, &[version]);
        client_config.alpn_protocols.clone_from(&client_protos);

        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config).await;

        assert_eq!(client.alpn_protocol(), None);
        assert_eq!(server.alpn_protocol(), None);
        let error = do_handshake_until_error(&mut client, &mut server).await;
        assert_eq!(client.alpn_protocol(), agreed);
        assert_eq!(server.alpn_protocol(), agreed);
        assert_eq!(error.err(), expected_error);
    }
}

async fn alpn_test(
    server_protos: Vec<Vec<u8>>,
    client_protos: Vec<Vec<u8>>,
    agreed: Option<&[u8]>,
) {
    alpn_test_error(server_protos, client_protos, agreed, None).await
}

#[tokio::test]
async fn alpn() {
    // no support
    alpn_test(vec![], vec![], None).await;

    // server support
    alpn_test(vec![b"server-proto".to_vec()], vec![], None).await;

    // client support
    alpn_test(vec![], vec![b"client-proto".to_vec()], None).await;

    // no overlap
    alpn_test_error(
        vec![b"server-proto".to_vec()],
        vec![b"client-proto".to_vec()],
        None,
        Some(ErrorFromPeer::Server(rustls::Error::NoApplicationProtocol)),
    )
    .await;

    // server chooses preference
    alpn_test(
        vec![b"server-proto".to_vec(), b"client-proto".to_vec()],
        vec![b"client-proto".to_vec(), b"server-proto".to_vec()],
        Some(b"server-proto"),
    )
    .await;

    // case sensitive
    alpn_test_error(
        vec![b"PROTO".to_vec()],
        vec![b"proto".to_vec()],
        None,
        Some(ErrorFromPeer::Server(rustls::Error::NoApplicationProtocol)),
    )
    .await;
}

async fn version_test(
    client_versions: &[&'static tls_client::SupportedProtocolVersion],
    server_versions: &[&'static rustls::SupportedProtocolVersion],
    result: Option<ProtocolVersion>,
) {
    let client_versions = if client_versions.is_empty() {
        tls_client::ALL_VERSIONS
    } else {
        client_versions
    };
    let server_versions = if server_versions.is_empty() {
        rustls::ALL_VERSIONS
    } else {
        server_versions
    };

    let client_config = make_client_config_with_versions(KeyType::Rsa, client_versions);
    let server_config = make_server_config_with_versions(KeyType::Rsa, server_versions);

    println!(
        "version {:?} {:?} -> {:?}",
        client_versions, server_versions, result
    );

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config).await;

    assert_eq!(client.protocol_version(), None);
    if result.is_none() {
        let err = do_handshake_until_error(&mut client, &mut server).await;
        assert!(err.is_err());
    } else {
        do_handshake(&mut client, &mut server).await;
        assert_eq!(client.protocol_version(), result);
    }
}

#[ignore = "needs to be fixed"]
#[tokio::test]
async fn versions() {
    // default -> 1.3
    version_test(&[], &[], Some(ProtocolVersion::TLSv1_3)).await;

    // client default, server 1.2 -> 1.2
    #[cfg(feature = "tls12")]
    version_test(
        &[],
        &[&rustls::version::TLS12],
        Some(ProtocolVersion::TLSv1_2),
    )
    .await;

    // client 1.2, server default -> 1.2
    #[cfg(feature = "tls12")]
    version_test(
        &[&tls_client::version::TLS12],
        &[],
        Some(ProtocolVersion::TLSv1_2),
    )
    .await;

    // client 1.2, server 1.3 -> fail
    #[cfg(feature = "tls12")]
    version_test(
        &[&tls_client::version::TLS12],
        &[&rustls::version::TLS13],
        None,
    )
    .await;

    // client 1.3, server 1.2 -> fail
    #[cfg(feature = "tls12")]
    version_test(
        &[&tls_client::version::TLS13],
        &[&rustls::version::TLS12],
        None,
    )
    .await;

    // client 1.3, server 1.2+1.3 -> 1.3
    #[cfg(feature = "tls12")]
    version_test(
        &[&tls_client::version::TLS13],
        &[&rustls::version::TLS12, &rustls::version::TLS13],
        Some(ProtocolVersion::TLSv1_3),
    )
    .await;

    // client 1.2+1.3, server 1.2 -> 1.2
    #[cfg(feature = "tls12")]
    version_test(
        &[&tls_client::version::TLS13, &tls_client::version::TLS12],
        &[&rustls::version::TLS12],
        Some(ProtocolVersion::TLSv1_2),
    )
    .await;
}

fn check_read(reader: &mut dyn io::Read, bytes: &[u8]) {
    let mut buf = vec![0u8; bytes.len() + 1];
    assert_eq!(bytes.len(), reader.read(&mut buf).unwrap());
    assert_eq!(bytes, &buf[..bytes.len()]);
}

#[test]
fn config_builder_for_client_rejects_empty_kx_groups() {
    assert_eq!(
        ClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_kx_groups(&[])
            .with_safe_default_protocol_versions()
            .err(),
        Some(Error::General("no kx groups configured".into()))
    );
}

#[test]
fn config_builder_for_client_rejects_empty_cipher_suites() {
    assert_eq!(
        ClientConfig::builder()
            .with_cipher_suites(&[])
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()
            .err(),
        Some(Error::General("no usable cipher suites configured".into()))
    );
}

#[cfg(feature = "tls12")]
#[test]
fn config_builder_for_client_rejects_incompatible_cipher_suites() {
    assert_eq!(
        ClientConfig::builder()
            .with_cipher_suites(&[tls_core::suites::TLS13_AES_256_GCM_SHA384])
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&tls_client::version::TLS12])
            .err(),
        Some(Error::General("no usable cipher suites configured".into()))
    );
}

#[tokio::test]
async fn servered_client_data_sent() {
    let server_config = Arc::new(make_server_config(KeyType::Rsa));

    for version in tls_client::ALL_VERSIONS {
        let client_config = make_client_config_with_versions(KeyType::Rsa, &[version]);
        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config).await;

        assert_eq!(5, client.write_plaintext(b"hello").await.unwrap());

        do_handshake(&mut client, &mut server).await;
        send(&mut client, &mut server);
        server.process_new_packets().unwrap();

        check_read(&mut server.reader(), b"hello");
    }
}

#[tokio::test]
async fn servered_server_data_sent() {
    let server_config = Arc::new(make_server_config(KeyType::Rsa));

    for version in tls_client::ALL_VERSIONS {
        let client_config = make_client_config_with_versions(KeyType::Rsa, &[version]);
        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config).await;

        assert_eq!(5, server.writer().write(b"hello").unwrap());

        do_handshake(&mut client, &mut server).await;
        receive(&mut server, &mut client);
        client.process_new_packets().await.unwrap();

        check_read(&mut client.reader(), b"hello");
    }
}

#[tokio::test]
async fn servered_both_data_sent() {
    let server_config = Arc::new(make_server_config(KeyType::Rsa));

    for version in tls_client::ALL_VERSIONS {
        let client_config = make_client_config_with_versions(KeyType::Rsa, &[version]);
        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config).await;

        assert_eq!(12, server.writer().write(b"from-server!").unwrap());
        assert_eq!(12, client.write_plaintext(b"from-client!").await.unwrap());

        do_handshake(&mut client, &mut server).await;

        receive(&mut server, &mut client);
        client.process_new_packets().await.unwrap();
        send(&mut client, &mut server);
        server.process_new_packets().unwrap();

        check_read(&mut client.reader(), b"from-server!");
        check_read(&mut server.reader(), b"from-client!");
    }
}

#[tokio::test]
async fn client_can_get_server_cert() {
    for kt in ALL_KEY_TYPES.iter() {
        for version in tls_client::ALL_VERSIONS {
            let client_config = make_client_config_with_versions(*kt, &[version]);
            let (mut client, mut server) =
                make_pair_for_configs(client_config, make_server_config(*kt)).await;
            do_handshake(&mut client, &mut server).await;

            let certs = client.peer_certificates();
            assert_eq!(certs, Some(kt.get_chain().as_slice()));
        }
    }
}

#[tokio::test]
async fn client_can_get_server_cert_after_resumption() {
    for kt in ALL_KEY_TYPES.iter() {
        let server_config = make_server_config(*kt);
        for version in tls_client::ALL_VERSIONS {
            let client_config = make_client_config_with_versions(*kt, &[version]);
            let (mut client, mut server) =
                make_pair_for_configs(client_config.clone(), server_config.clone()).await;
            do_handshake(&mut client, &mut server).await;

            let original_certs = client.peer_certificates();

            let (mut client, mut server) =
                make_pair_for_configs(client_config.clone(), server_config.clone()).await;
            do_handshake(&mut client, &mut server).await;

            let resumed_certs = client.peer_certificates();

            assert_eq!(original_certs, resumed_certs);
        }
    }
}

#[tokio::test]
async fn server_can_get_client_cert() {
    for kt in ALL_KEY_TYPES.iter() {
        let server_config = Arc::new(make_server_config_with_mandatory_client_auth(*kt));

        for version in tls_client::ALL_VERSIONS {
            let client_config = make_client_config_with_versions_with_auth(*kt, &[version]);
            let (mut client, mut server) =
                make_pair_for_arc_configs(&Arc::new(client_config), &server_config).await;
            do_handshake(&mut client, &mut server).await;

            let certs = server.peer_certificates();
            assert_eq!(certs, Some(kt.get_client_chain_rustls().as_slice()));
        }
    }
}

#[tokio::test]
async fn server_can_get_client_cert_after_resumption() {
    for kt in ALL_KEY_TYPES.iter() {
        let server_config = Arc::new(make_server_config_with_mandatory_client_auth(*kt));

        for version in tls_client::ALL_VERSIONS {
            let client_config = make_client_config_with_versions_with_auth(*kt, &[version]);
            let client_config = Arc::new(client_config);
            let (mut client, mut server) =
                make_pair_for_arc_configs(&client_config, &server_config).await;
            do_handshake(&mut client, &mut server).await;
            let original_certs = server.peer_certificates();

            let (mut client, mut server) =
                make_pair_for_arc_configs(&client_config, &server_config).await;
            do_handshake(&mut client, &mut server).await;
            let resumed_certs = server.peer_certificates();
            assert_eq!(original_certs, resumed_certs);
        }
    }
}

// /// Test that the server handles combination of `offer_client_auth()` returning true
// /// and `client_auth_mandatory` returning `Some(false)`. This exercises both the
// /// client's and server's ability to "recover" from the server asking for a client
// /// certificate and not being given one. This also covers the implementation
// /// of `AllowAnyAnonymousOrAuthenticatedClient`.
// #[tokio::test]
// fn server_allow_any_anonymous_or_authenticated_client() {
//     let kt = KeyType::Rsa;
//     for client_cert_chain in [None, Some(kt.get_client_chain())].iter() {
//         let client_auth_roots = get_client_root_store(kt);
//         let client_auth = AllowAnyAnonymousOrAuthenticatedClient::new(client_auth_roots);

//         let server_config = ServerConfig::builder()
//             .with_safe_defaults()
//             .with_client_cert_verifier(client_auth)
//             .with_single_cert(kt.get_chain_rustls(), kt.get_key_rustls())
//             .unwrap();
//         let server_config = Arc::new(server_config);

//         for version in tls_client::ALL_VERSIONS {
//             let client_config = if client_cert_chain.is_some() {
//                 make_client_config_with_versions_with_auth(kt, &[version])
//             } else {
//                 make_client_config_with_versions(kt, &[version])
//             };
//             let (mut client, mut server) =
//                 make_pair_for_arc_configs(&Arc::new(client_config), &server_config).await;
//             do_handshake(&mut client, &mut server).await;

//             let certs = server.peer_certificates();
//             assert_eq!(certs, client_cert_chain.as_deref());
//         }
//     }
// }

fn check_read_and_close(reader: &mut dyn io::Read, expect: &[u8]) {
    check_read(reader, expect);
    assert!(matches!(reader.read(&mut [0u8; 5]), Ok(0)));
}

#[tokio::test]
async fn server_close_notify() {
    let kt = KeyType::Rsa;
    let server_config = Arc::new(make_server_config_with_mandatory_client_auth(kt));

    for version in tls_client::ALL_VERSIONS {
        let client_config = make_client_config_with_versions_with_auth(kt, &[version]);
        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config).await;
        do_handshake(&mut client, &mut server).await;

        // check that alerts don't overtake appdata
        assert_eq!(12, server.writer().write(b"from-server!").unwrap());
        assert_eq!(12, client.write_plaintext(b"from-client!").await.unwrap());
        server.send_close_notify();

        receive(&mut server, &mut client);
        let io_state = client.process_new_packets().await.unwrap();
        assert!(io_state.peer_has_closed());
        check_read_and_close(&mut client.reader(), b"from-server!");

        send(&mut client, &mut server);
        server.process_new_packets().unwrap();
        check_read(&mut server.reader(), b"from-client!");
    }
}

#[ignore = "needs to be fixed"]
#[tokio::test]
async fn client_close_notify() {
    let kt = KeyType::Rsa;
    let server_config = Arc::new(make_server_config_with_mandatory_client_auth(kt));

    for version in tls_client::ALL_VERSIONS {
        let client_config = make_client_config_with_versions_with_auth(kt, &[version]);
        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config).await;
        do_handshake(&mut client, &mut server).await;

        // check that alerts don't overtake appdata
        assert_eq!(12, server.writer().write(b"from-server!").unwrap());
        assert_eq!(12, client.write_plaintext(b"from-client!").await.unwrap());
        client.send_close_notify().await.unwrap();

        send(&mut client, &mut server);
        let io_state = server.process_new_packets().unwrap();
        assert!(io_state.peer_has_closed());
        check_read_and_close(&mut server.reader(), b"from-client!");

        receive(&mut server, &mut client);
        client.process_new_packets().await.unwrap();
        check_read(&mut client.reader(), b"from-server!");
    }
}

#[tokio::test]
async fn server_closes_uncleanly() {
    let kt = KeyType::Rsa;
    let server_config = Arc::new(make_server_config(kt));

    for version in tls_client::ALL_VERSIONS {
        let client_config = make_client_config_with_versions(kt, &[version]);
        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config).await;
        do_handshake(&mut client, &mut server).await;

        // check that unclean EOF reporting does not overtake appdata
        assert_eq!(12, server.writer().write(b"from-server!").unwrap());
        assert_eq!(12, client.write_plaintext(b"from-client!").await.unwrap());

        receive(&mut server, &mut client);
        transfer_eof(&mut client);
        let io_state = client.process_new_packets().await.unwrap();
        assert!(!io_state.peer_has_closed());
        check_read(&mut client.reader(), b"from-server!");

        assert!(matches!(client.reader().read(&mut [0u8; 1]),
                         Err(err) if err.kind() == io::ErrorKind::UnexpectedEof));

        // may still transmit pending frames
        send(&mut client, &mut server);
        server.process_new_packets().unwrap();
        check_read(&mut server.reader(), b"from-client!");
    }
}

#[tokio::test]
async fn client_closes_uncleanly() {
    let kt = KeyType::Rsa;
    let server_config = Arc::new(make_server_config(kt));

    for version in tls_client::ALL_VERSIONS {
        let client_config = make_client_config_with_versions(kt, &[version]);
        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config).await;
        do_handshake(&mut client, &mut server).await;

        // check that unclean EOF reporting does not overtake appdata
        assert_eq!(12, server.writer().write(b"from-server!").unwrap());
        assert_eq!(12, client.write_plaintext(b"from-client!").await.unwrap());

        send(&mut client, &mut server);
        transfer_eof_rustls(&mut server);
        let io_state = server.process_new_packets().unwrap();
        assert!(!io_state.peer_has_closed());
        check_read(&mut server.reader(), b"from-client!");

        assert!(matches!(server.reader().read(&mut [0u8; 1]),
                         Err(err) if err.kind() == io::ErrorKind::UnexpectedEof));

        // may still transmit pending frames
        receive(&mut server, &mut client);
        client.process_new_packets().await.unwrap();
        check_read(&mut client.reader(), b"from-server!");
    }
}

#[derive(Default)]
struct ServerCheckCertResolve {
    expected_sni: Option<String>,
    expected_sigalgs: Option<Vec<rustls::SignatureScheme>>,
    expected_alpn: Option<Vec<Vec<u8>>>,
}

impl ResolvesServerCert for ServerCheckCertResolve {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<rustls::sign::CertifiedKey>> {
        if client_hello.signature_schemes().is_empty() {
            panic!("no signature schemes shared by client");
        }

        if let Some(expected_sni) = &self.expected_sni {
            let sni: &str = client_hello.server_name().expect("sni unexpectedly absent");
            assert_eq!(expected_sni, sni);
        }

        if let Some(expected_sigalgs) = &self.expected_sigalgs {
            if expected_sigalgs != client_hello.signature_schemes() {
                panic!(
                    "unexpected signature schemes (wanted {:?} got {:?})",
                    self.expected_sigalgs,
                    client_hello.signature_schemes()
                );
            }
        }

        if let Some(expected_alpn) = &self.expected_alpn {
            let alpn = client_hello
                .alpn()
                .expect("alpn unexpectedly absent")
                .collect::<Vec<_>>();
            assert_eq!(alpn.len(), expected_alpn.len());

            for (got, wanted) in alpn.iter().zip(expected_alpn.iter()) {
                assert_eq!(got, &wanted.as_slice());
            }
        }

        None
    }
}

#[tokio::test]
async fn server_cert_resolve_with_sni() {
    for kt in ALL_KEY_TYPES.iter() {
        let client_config = make_client_config(*kt);
        let mut server_config = make_server_config(*kt);

        server_config.cert_resolver = Arc::new(ServerCheckCertResolve {
            expected_sni: Some("the-value-from-sni".into()),
            ..Default::default()
        });

        let mut client = ClientConnection::new(
            Arc::new(client_config),
            Box::new(RustCryptoBackend::new()),
            dns_name("the-value-from-sni"),
        )
        .unwrap();
        client.start().await.unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        let err = do_handshake_until_error(&mut client, &mut server).await;
        assert!(err.is_err());
    }
}

#[tokio::test]
async fn server_cert_resolve_with_alpn() {
    for kt in ALL_KEY_TYPES.iter() {
        let mut client_config = make_client_config(*kt);
        client_config.alpn_protocols = vec!["foo".into(), "bar".into()];

        let mut server_config = make_server_config(*kt);
        server_config.cert_resolver = Arc::new(ServerCheckCertResolve {
            expected_alpn: Some(vec![b"foo".to_vec(), b"bar".to_vec()]),
            ..Default::default()
        });

        let mut client = ClientConnection::new(
            Arc::new(client_config),
            Box::new(RustCryptoBackend::new()),
            dns_name("sni-value"),
        )
        .unwrap();
        client.start().await.unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        let err = do_handshake_until_error(&mut client, &mut server).await;
        assert!(err.is_err());
    }
}

#[tokio::test]
async fn client_trims_terminating_dot() {
    for kt in ALL_KEY_TYPES.iter() {
        let client_config = make_client_config(*kt);
        let mut server_config = make_server_config(*kt);

        server_config.cert_resolver = Arc::new(ServerCheckCertResolve {
            expected_sni: Some("some-host.com".into()),
            ..Default::default()
        });

        let mut client = ClientConnection::new(
            Arc::new(client_config),
            Box::new(RustCryptoBackend::new()),
            dns_name("some-host.com."),
        )
        .unwrap();
        client.start().await.unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        let err = do_handshake_until_error(&mut client, &mut server).await;
        assert!(err.is_err());
    }
}

#[cfg(feature = "tls12")]
async fn check_sigalgs_reduced_by_ciphersuite(
    kt: KeyType,
    suite: CipherSuite,
    expected_sigalgs: Vec<rustls::SignatureScheme>,
) {
    let client_config = finish_client_config(
        kt,
        ClientConfig::builder()
            .with_cipher_suites(&[find_suite(suite)])
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()
            .unwrap(),
    );

    let mut server_config = make_server_config(kt);

    server_config.cert_resolver = Arc::new(ServerCheckCertResolve {
        expected_sigalgs: Some(expected_sigalgs),
        ..Default::default()
    });

    let mut client = ClientConnection::new(
        Arc::new(client_config),
        Box::new(RustCryptoBackend::new()),
        dns_name("localhost"),
    )
    .unwrap();
    client.start().await.unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

    let err = do_handshake_until_error(&mut client, &mut server).await;
    assert!(err.is_err());
}

#[ignore = "needs to be fixed"]
#[cfg(feature = "tls12")]
#[tokio::test]
async fn server_cert_resolve_reduces_sigalgs_for_rsa_ciphersuite() {
    check_sigalgs_reduced_by_ciphersuite(
        KeyType::Rsa,
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        vec![
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ],
    )
    .await;
}

#[ignore = "needs to be fixed"]
#[cfg(feature = "tls12")]
#[tokio::test]
async fn server_cert_resolve_reduces_sigalgs_for_ecdsa_ciphersuite() {
    check_sigalgs_reduced_by_ciphersuite(
        KeyType::Ecdsa,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        vec![
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ],
    )
    .await;
}

struct ServerCheckNoSNI {}

impl ResolvesServerCert for ServerCheckNoSNI {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<rustls::sign::CertifiedKey>> {
        assert!(client_hello.server_name().is_none());

        None
    }
}

#[tokio::test]
async fn client_with_sni_disabled_does_not_send_sni() {
    for kt in ALL_KEY_TYPES.iter() {
        let mut server_config = make_server_config(*kt);
        server_config.cert_resolver = Arc::new(ServerCheckNoSNI {});
        let server_config = Arc::new(server_config);

        for version in tls_client::ALL_VERSIONS {
            let mut client_config = make_client_config_with_versions(*kt, &[version]);
            client_config.enable_sni = false;

            let mut client = ClientConnection::new(
                Arc::new(client_config),
                Box::new(RustCryptoBackend::new()),
                dns_name("value-not-sent"),
            )
            .unwrap();
            client.start().await.unwrap();
            let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();

            let err = do_handshake_until_error(&mut client, &mut server).await;
            assert!(err.is_err());
        }
    }
}

#[tokio::test]
async fn client_checks_server_certificate_with_given_name() {
    for kt in ALL_KEY_TYPES.iter() {
        let server_config = Arc::new(make_server_config(*kt));

        for version in tls_client::ALL_VERSIONS {
            let client_config = make_client_config_with_versions(*kt, &[version]);
            let mut client = ClientConnection::new(
                Arc::new(client_config),
                Box::new(RustCryptoBackend::new()),
                dns_name("not-the-right-hostname.com"),
            )
            .unwrap();
            client.start().await.unwrap();
            let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();

            let err = do_handshake_until_error(&mut client, &mut server).await;
            assert_eq!(
                err,
                Err(ErrorFromPeer::Client(Error::CoreError(
                    tls_core::Error::InvalidCertificateData(
                        "invalid peer certificate: CertNotValidForName".into(),
                    )
                )))
            );
        }
    }
}

struct ClientCheckCertResolve {
    query_count: AtomicUsize,
    expect_queries: usize,
}

impl ClientCheckCertResolve {
    fn new(expect_queries: usize) -> Self {
        ClientCheckCertResolve {
            query_count: AtomicUsize::new(0),
            expect_queries,
        }
    }
}

impl Drop for ClientCheckCertResolve {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let count = self.query_count.load(Ordering::SeqCst);
            assert_eq!(count, self.expect_queries);
        }
    }
}

impl ResolvesClientCert for ClientCheckCertResolve {
    fn resolve(
        &self,
        acceptable_issuers: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<sign::CertifiedKey>> {
        self.query_count.fetch_add(1, Ordering::SeqCst);

        if acceptable_issuers.is_empty() {
            panic!("no issuers offered by server");
        }

        if sigschemes.is_empty() {
            panic!("no signature schemes shared by server");
        }

        None
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn client_cert_resolve() {
    for kt in ALL_KEY_TYPES.iter() {
        let server_config = Arc::new(make_server_config_with_mandatory_client_auth(*kt));

        for version in tls_client::ALL_VERSIONS {
            let mut client_config = make_client_config_with_versions(*kt, &[version]);
            client_config.client_auth_cert_resolver = Arc::new(ClientCheckCertResolve::new(1));

            let (mut client, mut server) =
                make_pair_for_arc_configs(&Arc::new(client_config), &server_config).await;

            assert_eq!(
                do_handshake_until_error(&mut client, &mut server).await,
                Err(ErrorFromPeer::Server(
                    rustls::Error::NoCertificatesPresented
                ))
            );
        }
    }
}

#[tokio::test]
async fn client_auth_works() {
    for kt in ALL_KEY_TYPES.iter() {
        let server_config = Arc::new(make_server_config_with_mandatory_client_auth(*kt));

        for version in tls_client::ALL_VERSIONS {
            let client_config = make_client_config_with_versions_with_auth(*kt, &[version]);
            let (mut client, mut server) =
                make_pair_for_arc_configs(&Arc::new(client_config), &server_config).await;
            do_handshake(&mut client, &mut server).await;
        }
    }
}

#[tokio::test]
async fn client_error_is_sticky() {
    let (mut client, _) = make_pair(KeyType::Rsa).await;
    client
        .read_tls(&mut b"\x16\x03\x03\x00\x08\x0f\x00\x00\x04junk".as_ref())
        .unwrap();
    let mut err = client.process_new_packets().await;
    assert!(err.is_err());
    err = client.process_new_packets().await;
    assert!(err.is_err());
}

#[tokio::test]
#[allow(clippy::no_effect)]
async fn client_is_send() {
    let (client, _) = make_pair(KeyType::Rsa).await;
    &client as &dyn Send;
}

#[tokio::test]
async fn client_respects_buffer_limit_pre_handshake() {
    let (mut client, mut server) = make_pair(KeyType::Rsa).await;

    client.set_buffer_limit(Some(32));

    assert_eq!(
        client
            .write_plaintext(b"01234567890123456789")
            .await
            .unwrap(),
        20
    );
    assert_eq!(
        client
            .write_plaintext(b"01234567890123456789")
            .await
            .unwrap(),
        12
    );

    do_handshake(&mut client, &mut server).await;
    send(&mut client, &mut server);
    server.process_new_packets().unwrap();

    check_read(&mut server.reader(), b"01234567890123456789012345678901");
}

// #[tokio::test]
// async fn client_respects_buffer_limit_pre_handshake_with_vectored_write() {
//     let (mut client, mut server) = make_pair(KeyType::Rsa).await;

//     client.set_buffer_limit(Some(32));

//     assert_eq!(
//         client
//             .write_vectored(&[
//                 IoSlice::new(b"01234567890123456789"),
//                 IoSlice::new(b"01234567890123456789")
//             ]).await
//             .unwrap(),
//         32
//     );

//     do_handshake(&mut client, &mut server).await;
//     send(&mut client, &mut server);
//     server.process_new_packets().unwrap();

//     check_read(&mut server.reader(), b"01234567890123456789012345678901");
// }

#[ignore = "needs to be fixed"]
#[tokio::test]
async fn client_respects_buffer_limit_post_handshake() {
    let (mut client, mut server) = make_pair(KeyType::Rsa).await;

    do_handshake(&mut client, &mut server).await;
    client.set_buffer_limit(Some(48));

    assert_eq!(
        client
            .write_plaintext(b"01234567890123456789")
            .await
            .unwrap(),
        20
    );
    assert_eq!(
        client
            .write_plaintext(b"01234567890123456789")
            .await
            .unwrap(),
        6
    );

    send(&mut client, &mut server);
    server.process_new_packets().unwrap();

    check_read(&mut server.reader(), b"01234567890123456789012345");
}

struct ServerSession<'a, C, S>
where
    C: DerefMut + Deref<Target = rustls::ConnectionCommon<S>>,
    S: rustls::SideData,
{
    sess: &'a mut C,
    pub reads: usize,
    pub writevs: Vec<Vec<usize>>,
    fail_ok: bool,
    pub short_writes: bool,
    pub last_error: Option<rustls::Error>,
}

impl<'a, C, S> ServerSession<'a, C, S>
where
    C: DerefMut + Deref<Target = rustls::ConnectionCommon<S>>,
    S: rustls::SideData,
{
    fn new(sess: &'a mut C) -> ServerSession<'a, C, S> {
        ServerSession {
            sess,
            reads: 0,
            writevs: vec![],
            fail_ok: false,
            short_writes: false,
            last_error: None,
        }
    }

    fn _new_fails(sess: &'a mut C) -> ServerSession<'a, C, S> {
        let mut os = ServerSession::new(sess);
        os.fail_ok = true;
        os
    }
}

impl<'a, C, S> io::Read for ServerSession<'a, C, S>
where
    C: DerefMut + Deref<Target = rustls::ConnectionCommon<S>>,
    S: rustls::SideData,
{
    fn read(&mut self, mut b: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        self.sess.write_tls(b.by_ref())
    }
}

impl<'a, C, S> io::Write for ServerSession<'a, C, S>
where
    C: DerefMut + Deref<Target = rustls::ConnectionCommon<S>>,
    S: rustls::SideData,
{
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        unreachable!()
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn write_vectored(&mut self, b: &[io::IoSlice<'_>]) -> io::Result<usize> {
        let mut total = 0;
        let mut lengths = vec![];
        for bytes in b {
            let write_len = if self.short_writes {
                if bytes.len() > 5 {
                    bytes.len() / 2
                } else {
                    bytes.len()
                }
            } else {
                bytes.len()
            };

            let l = self
                .sess
                .read_tls(&mut io::Cursor::new(&bytes[..write_len]))?;
            lengths.push(l);
            total += l;
            if bytes.len() != l {
                break;
            }
        }

        let rc = self.sess.process_new_packets();
        if !self.fail_ok {
            rc.unwrap();
        } else if rc.is_err() {
            self.last_error = rc.err();
        }

        self.writevs.push(lengths);
        Ok(total)
    }
}

struct ClientSession<'a, C>
where
    C: DerefMut + Deref<Target = tls_client::ConnectionCommon>,
{
    sess: &'a mut C,
    pub reads: usize,
    pub writevs: Vec<Vec<usize>>,
    fail_ok: bool,
    pub short_writes: bool,
    pub last_error: Option<tls_client::Error>,
}

impl<'a, C> ClientSession<'a, C>
where
    C: DerefMut + Deref<Target = tls_client::ConnectionCommon>,
{
    fn new(sess: &'a mut C) -> ClientSession<'a, C> {
        ClientSession {
            sess,
            reads: 0,
            writevs: vec![],
            fail_ok: false,
            short_writes: false,
            last_error: None,
        }
    }

    fn _new_fails(sess: &'a mut C) -> ClientSession<'a, C> {
        let mut os = ClientSession::new(sess);
        os.fail_ok = true;
        os
    }
}

impl<'a, C> io::Read for ClientSession<'a, C>
where
    C: DerefMut + Deref<Target = tls_client::ConnectionCommon>,
{
    fn read(&mut self, mut b: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        self.sess.write_tls(b.by_ref())
    }
}

impl<'a, C> io::Write for ClientSession<'a, C>
where
    C: DerefMut + Deref<Target = tls_client::ConnectionCommon>,
{
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        unreachable!()
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        let mut total = 0;
        let mut lengths = vec![];
        for bytes in bufs {
            let write_len = if self.short_writes {
                if bytes.len() > 5 {
                    bytes.len() / 2
                } else {
                    bytes.len()
                }
            } else {
                bytes.len()
            };

            let l = self
                .sess
                .read_tls(&mut io::Cursor::new(&bytes[..write_len]))?;
            lengths.push(l);
            total += l;
            if bytes.len() != l {
                break;
            }
        }

        let rc = futures::executor::block_on(self.sess.process_new_packets());
        if !self.fail_ok {
            rc.unwrap();
        } else if rc.is_err() {
            self.last_error = rc.err();
        }

        self.writevs.push(lengths);
        Ok(total)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn client_read_returns_wouldblock_when_no_data() {
    let (mut client, _) = make_pair(KeyType::Rsa).await;
    assert!(matches!(client.reader().read(&mut [0u8; 1]),
                     Err(err) if err.kind() == io::ErrorKind::WouldBlock));
}

#[ignore = "needs to be fixed"]
#[tokio::test]
async fn client_returns_initial_io_state() {
    let (mut client, _) = make_pair(KeyType::Rsa).await;
    let io_state = client.process_new_packets().await.unwrap();
    println!("IoState is Debug {:?}", io_state);
    assert_eq!(io_state.plaintext_bytes_to_read(), 0);
    assert!(!io_state.peer_has_closed());
    assert!(io_state.tls_bytes_to_write() > 200);
}

#[tokio::test]
async fn client_complete_io_for_handshake() {
    let (mut client, mut server) = make_pair(KeyType::Rsa).await;

    assert!(client.is_handshaking());
    let (rdlen, wrlen) = client
        .complete_io(&mut BlockingIo(ServerSession::new(&mut server)))
        .await
        .unwrap();
    assert!(rdlen > 0 && wrlen > 0);
    assert!(!client.is_handshaking());
}

#[tokio::test]
async fn client_complete_io_for_handshake_eof() {
    let (mut client, _) = make_pair(KeyType::Rsa).await;
    let mut input = futures::io::Cursor::new(Vec::new());

    assert!(client.is_handshaking());
    let err = client.complete_io(&mut input).await.unwrap_err();
    assert_eq!(io::ErrorKind::UnexpectedEof, err.kind());
}

#[ignore = "needs to be fixed"]
#[tokio::test]
async fn client_complete_io_for_write() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt).await;

        do_handshake(&mut client, &mut server).await;

        client
            .write_plaintext(b"01234567890123456789")
            .await
            .unwrap();
        client
            .write_plaintext(b"01234567890123456789")
            .await
            .unwrap();
        {
            let mut pipe = ServerSession::new(&mut server);
            let (rdlen, wrlen) = client
                .complete_io(&mut BlockingIo(&mut pipe))
                .await
                .unwrap();
            assert!(rdlen == 0 && wrlen > 0);
            println!("{:?}", pipe.writevs);
            assert_eq!(pipe.writevs, vec![vec![42, 42]]);
        }
        check_read(
            &mut server.reader(),
            b"0123456789012345678901234567890123456789",
        );
    }
}

#[ignore = "needs to be fixed"]
#[tokio::test]
async fn client_complete_io_for_read() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt).await;

        do_handshake(&mut client, &mut server).await;

        server.writer().write_all(b"01234567890123456789").unwrap();
        {
            let mut pipe = ServerSession::new(&mut server);
            let (rdlen, wrlen) = client
                .complete_io(&mut BlockingIo(&mut pipe))
                .await
                .unwrap();
            assert!(rdlen > 0 && wrlen == 0);
            assert_eq!(pipe.reads, 1);
        }
        check_read(&mut client.reader(), b"01234567890123456789");
    }
}

// #[tokio::test]
// async fn client_stream_write() {
//     for kt in ALL_KEY_TYPES.iter() {
//         let (mut client, mut server) = make_pair(*kt).await;

//         {
//             let mut pipe = ServerSession::new(&mut server);
//             let mut stream = Stream::new(&mut client, &mut pipe);
//             assert_eq!(stream.write(b"hello").unwrap(), 5);
//         }
//         check_read(&mut server.reader(), b"hello");
//     }
// }

// #[tokio::test]
// async fn client_streamowned_write() {
//     for kt in ALL_KEY_TYPES.iter() {
//         let (client, mut server) = make_pair(*kt).await;

//         {
//             let pipe = ServerSession::new(&mut server);
//             let mut stream = StreamOwned::new(client, pipe);
//             assert_eq!(stream.write(b"hello").unwrap(), 5);
//         }
//         check_read(&mut server.reader(), b"hello");
//     }
// }

// #[tokio::test]
// async fn client_stream_read() {
//     for kt in ALL_KEY_TYPES.iter() {
//         let (mut client, mut server) = make_pair(*kt).await;

//         server.writer().write_all(b"world").unwrap();

//         {
//             let mut pipe = ServerSession::new(&mut server);
//             let mut stream = Stream::new(&mut client, &mut pipe);
//             check_read(&mut stream, b"world");
//         }
//     }
// }

// #[tokio::test]
// async fn client_streamowned_read() {
//     for kt in ALL_KEY_TYPES.iter() {
//         let (client, mut server) = make_pair(*kt).await;

//         server.writer().write_all(b"world").unwrap();

//         {
//             let pipe = ServerSession::new(&mut server);
//             let mut stream = StreamOwned::new(client, pipe);
//             check_read(&mut stream, b"world");
//         }
//     }
// }

#[tokio::test]
async fn server_stream_write() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt).await;

        {
            let mut pipe = ClientSession::new(&mut client);
            let mut stream = rustls::Stream::new(&mut server, &mut pipe);
            assert_eq!(stream.write(b"hello").unwrap(), 5);
        }
        check_read(&mut client.reader(), b"hello");
    }
}

#[tokio::test]
async fn server_streamowned_write() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, server) = make_pair(*kt).await;

        {
            let pipe = ClientSession::new(&mut client);
            let mut stream = rustls::StreamOwned::new(server, pipe);
            assert_eq!(stream.write(b"hello").unwrap(), 5);
        }
        check_read(&mut client.reader(), b"hello");
    }
}

#[tokio::test]
async fn server_stream_read() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt).await;

        client.write_all_plaintext(b"world").await.unwrap();

        {
            let mut pipe = ClientSession::new(&mut client);
            let mut stream = rustls::Stream::new(&mut server, &mut pipe);
            check_read(&mut stream, b"world");
        }
    }
}

#[tokio::test]
async fn server_streamowned_read() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, server) = make_pair(*kt).await;

        client.write_all_plaintext(b"world").await.unwrap();

        {
            let pipe = ClientSession::new(&mut client);
            let mut stream = rustls::StreamOwned::new(server, pipe);
            check_read(&mut stream, b"world");
        }
    }
}

// #[tokio::test]
// async fn stream_write_reports_underlying_io_error_before_plaintext_processed() {
//     let (mut client, mut server) = make_pair(KeyType::Rsa).await;
//     do_handshake(&mut client, &mut server).await;

//     let mut pipe = FailsWrites {
//         errkind: io::ErrorKind::ConnectionAborted,
//         after: 0,
//     };
//     client.write_all_plaintext(b"hello").await.unwrap();
//     let mut client_stream = Stream::new(&mut client, &mut pipe);
//     let rc = client_stream.write(b"world");
//     assert!(rc.is_err());
//     let err = rc.err().unwrap();
//     assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
// }

// #[tokio::test]
// async fn stream_write_swallows_underlying_io_error_after_plaintext_processed() {
//     let (mut client, mut server) = make_pair(KeyType::Rsa).await;
//     do_handshake(&mut client, &mut server).await;

//     let mut pipe = FailsWrites {
//         errkind: io::ErrorKind::ConnectionAborted,
//         after: 1,
//     };
//     client.write_all_plaintext(b"hello").await.unwrap();
//     let mut client_stream = Stream::new(&mut client, &mut pipe);
//     let rc = client_stream.write(b"world");
//     assert_eq!(format!("{:?}", rc), "Ok(5)");
// }

// fn make_disjoint_suite_configs() -> (ClientConfig, ServerConfig) {
//     let kt = KeyType::Rsa;
//     let server_config = finish_server_config(
//         kt,
//         ServerConfig::builder()
//             .with_cipher_suites(&[rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256])
//             .with_safe_default_kx_groups()
//             .with_safe_default_protocol_versions()
//             .unwrap(),
//     );

//     let client_config = finish_client_config(
//         kt,
//         ClientConfig::builder()
//             .with_cipher_suites(&[tls_client::cipher_suite::TLS13_AES_256_GCM_SHA384])
//             .with_safe_default_kx_groups()
//             .with_safe_default_protocol_versions()
//             .unwrap(),
//     );

//     (client_config, server_config)
// }

// #[tokio::test]
// async fn client_stream_handshake_error() {
//     let (client_config, server_config) = make_disjoint_suite_configs();
//     let (mut client, mut server) = make_pair_for_configs(client_config, server_config).await;

//     {
//         let mut pipe = ServerSession::new_fails(&mut server);
//         let mut client_stream = Stream::new(&mut client, &mut pipe);
//         let rc = client_stream.write(b"hello");
//         assert!(rc.is_err());
//         assert_eq!(
//             format!("{:?}", rc),
//             "Err(Custom { kind: InvalidData, error: AlertReceived(HandshakeFailure) })"
//         );
//         let rc = client_stream.write(b"hello");
//         assert!(rc.is_err());
//         assert_eq!(
//             format!("{:?}", rc),
//             "Err(Custom { kind: InvalidData, error: AlertReceived(HandshakeFailure) })"
//         );
//     }
// }

// #[tokio::test]
// async fn client_streamowned_handshake_error() {
//     let (client_config, server_config) = make_disjoint_suite_configs();
//     let (client, mut server) = make_pair_for_configs(client_config, server_config).await;

//     let pipe = ServerSession::new_fails(&mut server);
//     let mut client_stream = StreamOwned::new(client, pipe);
//     let rc = client_stream.write(b"hello");
//     assert!(rc.is_err());
//     assert_eq!(
//         format!("{:?}", rc),
//         "Err(Custom { kind: InvalidData, error: AlertReceived(HandshakeFailure) })"
//     );
//     let rc = client_stream.write(b"hello");
//     assert!(rc.is_err());
//     assert_eq!(
//         format!("{:?}", rc),
//         "Err(Custom { kind: InvalidData, error: AlertReceived(HandshakeFailure) })"
//     );
// }

#[tokio::test]
async fn client_config_is_clone() {
    let _ = make_client_config(KeyType::Rsa);
}

#[tokio::test]
async fn client_connection_is_debug() {
    let (client, _) = make_pair(KeyType::Rsa).await;
    println!("{:?}", client);
}

async fn do_exporter_test(client_config: ClientConfig, server_config: ServerConfig) {
    let mut client_secret = [0u8; 64];
    let mut server_secret = [0u8; 64];

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config).await;

    assert_eq!(
        Err(Error::HandshakeNotComplete),
        client.export_keying_material(&mut client_secret, b"label", Some(b"context"))
    );
    assert_eq!(
        Err(rustls::Error::HandshakeNotComplete),
        server.export_keying_material(&mut server_secret, b"label", Some(b"context"))
    );
    do_handshake(&mut client, &mut server).await;

    assert_eq!(
        Ok(()),
        client.export_keying_material(&mut client_secret, b"label", Some(b"context"))
    );
    assert_eq!(
        Ok(()),
        server.export_keying_material(&mut server_secret, b"label", Some(b"context"))
    );
    assert_eq!(client_secret.to_vec(), server_secret.to_vec());

    assert_eq!(
        Ok(()),
        client.export_keying_material(&mut client_secret, b"label", None)
    );
    assert_ne!(client_secret.to_vec(), server_secret.to_vec());
    assert_eq!(
        Ok(()),
        server.export_keying_material(&mut server_secret, b"label", None)
    );
    assert_eq!(client_secret.to_vec(), server_secret.to_vec());
}

#[ignore = "needs to be fixed"]
#[cfg(feature = "tls12")]
#[tokio::test]
async fn test_tls12_exporter() {
    for kt in ALL_KEY_TYPES.iter() {
        let client_config = make_client_config_with_versions(*kt, &[&tls_client::version::TLS12]);
        let server_config = make_server_config(*kt);

        do_exporter_test(client_config, server_config).await;
    }
}

#[ignore = "needs to be fixed"]
#[tokio::test]
async fn test_tls13_exporter() {
    for kt in ALL_KEY_TYPES.iter() {
        let client_config = make_client_config_with_versions(*kt, &[&tls_client::version::TLS13]);
        let server_config = make_server_config(*kt);

        do_exporter_test(client_config, server_config).await;
    }
}

async fn do_suite_test(
    client_config: ClientConfig,
    server_config: ServerConfig,
    expect_suite: SupportedCipherSuite,
    expect_version: ProtocolVersion,
) {
    println!(
        "do_suite_test {:?} {:?}",
        expect_version,
        expect_suite.suite()
    );
    let (mut client, mut server) = make_pair_for_configs(client_config, server_config).await;

    assert_eq!(None, client.negotiated_cipher_suite());
    assert_eq!(None, server.negotiated_cipher_suite());
    assert_eq!(None, client.protocol_version());
    assert_eq!(None, version_compat(server.protocol_version()));
    assert!(client.is_handshaking());
    assert!(server.is_handshaking());

    send(&mut client, &mut server);
    server.process_new_packets().unwrap();

    assert!(client.is_handshaking());
    assert!(server.is_handshaking());
    assert_eq!(None, client.protocol_version());
    assert_eq!(
        Some(expect_version),
        version_compat(server.protocol_version())
    );
    assert_eq!(None, client.negotiated_cipher_suite());
    // assert_eq!(Some(expect_suite), server.negotiated_cipher_suite());

    receive(&mut server, &mut client);
    client.process_new_packets().await.unwrap();

    assert_eq!(Some(expect_suite), client.negotiated_cipher_suite());
    // assert_eq!(Some(expect_suite), server.negotiated_cipher_suite());

    send(&mut client, &mut server);
    server.process_new_packets().unwrap();
    receive(&mut server, &mut client);
    client.process_new_packets().await.unwrap();

    assert!(!client.is_handshaking());
    assert!(!server.is_handshaking());
    assert_eq!(Some(expect_version), client.protocol_version());
    assert_eq!(
        Some(expect_version),
        version_compat(server.protocol_version())
    );
    assert_eq!(Some(expect_suite), client.negotiated_cipher_suite());
    // assert_eq!(Some(expect_suite), server.negotiated_cipher_suite());
}

fn find_suite(suite: CipherSuite) -> SupportedCipherSuite {
    for scs in ALL_CIPHER_SUITES.iter().copied() {
        if scs.suite() == suite {
            return scs;
        }
    }

    panic!("find_suite given unsupported suite");
}

static TEST_CIPHERSUITES: &[(&tls_client::SupportedProtocolVersion, KeyType, CipherSuite)] = &[
    // (
    //     &tls_client::version::TLS13,
    //     KeyType::Rsa,
    //     CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    // ),
    // (
    //     &tls_client::version::TLS13,
    //     KeyType::Rsa,
    //     CipherSuite::TLS13_AES_256_GCM_SHA384,
    // ),
    // (
    //     &tls_client::version::TLS13,
    //     KeyType::Rsa,
    //     CipherSuite::TLS13_AES_128_GCM_SHA256,
    // ),
    // #[cfg(feature = "tls12")]
    // (
    //     &tls_client::version::TLS12,
    //     KeyType::Ecdsa,
    //     CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    // ),
    // #[cfg(feature = "tls12")]
    // (
    //     &tls_client::version::TLS12,
    //     KeyType::Rsa,
    //     CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    // ),
    // #[cfg(feature = "tls12")]
    // (
    //     &tls_client::version::TLS12,
    //     KeyType::Ecdsa,
    //     CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    // ),
    #[cfg(feature = "tls12")]
    (
        &tls_client::version::TLS12,
        KeyType::Ecdsa,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    ),
    // #[cfg(feature = "tls12")]
    // (
    //     &tls_client::version::TLS12,
    //     KeyType::Rsa,
    //     CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    // ),
    #[cfg(feature = "tls12")]
    (
        &tls_client::version::TLS12,
        KeyType::Rsa,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    ),
];

#[ignore = "needs to be fixed"]
#[tokio::test]
async fn negotiated_ciphersuite_default() {
    for kt in ALL_KEY_TYPES.iter() {
        do_suite_test(
            make_client_config(*kt),
            make_server_config(*kt),
            find_suite(CipherSuite::TLS13_AES_256_GCM_SHA384),
            ProtocolVersion::TLSv1_3,
        )
        .await;
    }
}

#[test]
fn all_suites_covered() {
    assert_eq!(ALL_CIPHER_SUITES.len(), TEST_CIPHERSUITES.len());
}

#[tokio::test]
async fn negotiated_ciphersuite_client() {
    for item in TEST_CIPHERSUITES.iter() {
        let (version, kt, suite) = *item;
        let scs = find_suite(suite);
        let client_config = finish_client_config(
            kt,
            ClientConfig::builder()
                .with_cipher_suites(&[scs])
                .with_safe_default_kx_groups()
                .with_protocol_versions(&[version])
                .unwrap(),
        );

        do_suite_test(client_config, make_server_config(kt), scs, version.version).await;
    }
}

#[derive(Debug, PartialEq)]
struct KeyLogItem {
    label: String,
    client_random: Vec<u8>,
    secret: Vec<u8>,
}

struct KeyLogToVec {
    label: &'static str,
    items: Mutex<Vec<KeyLogItem>>,
}

impl KeyLogToVec {
    fn new(who: &'static str) -> Self {
        KeyLogToVec {
            label: who,
            items: Mutex::new(vec![]),
        }
    }

    fn take(&self) -> Vec<KeyLogItem> {
        std::mem::take(&mut self.items.lock().unwrap())
    }
}

impl KeyLog for KeyLogToVec {
    fn log(&self, label: &str, client: &[u8], secret: &[u8]) {
        let value = KeyLogItem {
            label: label.into(),
            client_random: client.into(),
            secret: secret.into(),
        };

        println!("key log {:?}: {:?}", self.label, value);

        self.items.lock().unwrap().push(value);
    }
}

impl rustls::KeyLog for KeyLogToVec {
    fn log(&self, label: &str, client: &[u8], secret: &[u8]) {
        let value = KeyLogItem {
            label: label.into(),
            client_random: client.into(),
            secret: secret.into(),
        };

        println!("key log {:?}: {:?}", self.label, value);

        self.items.lock().unwrap().push(value);
    }
}

#[ignore = "needs to be fixed"]
#[cfg(feature = "tls12")]
#[tokio::test]
async fn key_log_for_tls12() {
    let client_key_log = Arc::new(KeyLogToVec::new("client"));
    let server_key_log = Arc::new(KeyLogToVec::new("server"));

    let kt = KeyType::Rsa;
    let mut client_config = make_client_config_with_versions(kt, &[&tls_client::version::TLS12]);
    client_config.key_log = client_key_log.clone();
    let client_config = Arc::new(client_config);

    let mut server_config = make_server_config(kt);
    server_config.key_log = server_key_log.clone();
    let server_config = Arc::new(server_config);

    // full handshake
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config).await;
    do_handshake(&mut client, &mut server).await;

    let client_full_log = client_key_log.take();
    let server_full_log = server_key_log.take();
    assert_eq!(client_full_log, server_full_log);
    assert_eq!(1, client_full_log.len());
    assert_eq!("CLIENT_RANDOM", client_full_log[0].label);

    // resumed
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config).await;
    do_handshake(&mut client, &mut server).await;

    let client_resume_log = client_key_log.take();
    let server_resume_log = server_key_log.take();
    assert_eq!(client_resume_log, server_resume_log);
    assert_eq!(1, client_resume_log.len());
    assert_eq!("CLIENT_RANDOM", client_resume_log[0].label);
    assert_eq!(client_full_log[0].secret, client_resume_log[0].secret);
}

#[ignore = "needs to be fixed"]
#[tokio::test]
async fn key_log_for_tls13() {
    let client_key_log = Arc::new(KeyLogToVec::new("client"));
    let server_key_log = Arc::new(KeyLogToVec::new("server"));

    let kt = KeyType::Rsa;
    let mut client_config = make_client_config_with_versions(kt, &[&tls_client::version::TLS13]);
    client_config.key_log = client_key_log.clone();
    let client_config = Arc::new(client_config);

    let mut server_config = make_server_config(kt);
    server_config.key_log = server_key_log.clone();
    let server_config = Arc::new(server_config);

    // full handshake
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config).await;
    do_handshake(&mut client, &mut server).await;

    let client_full_log = client_key_log.take();
    let server_full_log = server_key_log.take();

    assert_eq!(5, client_full_log.len());
    assert_eq!("CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_full_log[0].label);
    assert_eq!("SERVER_HANDSHAKE_TRAFFIC_SECRET", client_full_log[1].label);
    assert_eq!("CLIENT_TRAFFIC_SECRET_0", client_full_log[2].label);
    assert_eq!("SERVER_TRAFFIC_SECRET_0", client_full_log[3].label);
    assert_eq!("EXPORTER_SECRET", client_full_log[4].label);

    assert_eq!(client_full_log[0], server_full_log[0]);
    assert_eq!(client_full_log[1], server_full_log[1]);
    assert_eq!(client_full_log[2], server_full_log[2]);
    assert_eq!(client_full_log[3], server_full_log[3]);
    assert_eq!(client_full_log[4], server_full_log[4]);

    // resumed
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config).await;
    do_handshake(&mut client, &mut server).await;

    let client_resume_log = client_key_log.take();
    let server_resume_log = server_key_log.take();

    assert_eq!(5, client_resume_log.len());
    assert_eq!(
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        client_resume_log[0].label
    );
    assert_eq!(
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        client_resume_log[1].label
    );
    assert_eq!("CLIENT_TRAFFIC_SECRET_0", client_resume_log[2].label);
    assert_eq!("SERVER_TRAFFIC_SECRET_0", client_resume_log[3].label);
    assert_eq!("EXPORTER_SECRET", client_resume_log[4].label);

    assert_eq!(6, server_resume_log.len());
    assert_eq!("CLIENT_EARLY_TRAFFIC_SECRET", server_resume_log[0].label);
    assert_eq!(
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        server_resume_log[1].label
    );
    assert_eq!(
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        server_resume_log[2].label
    );
    assert_eq!("CLIENT_TRAFFIC_SECRET_0", server_resume_log[3].label);
    assert_eq!("SERVER_TRAFFIC_SECRET_0", server_resume_log[4].label);
    assert_eq!("EXPORTER_SECRET", server_resume_log[5].label);

    assert_eq!(client_resume_log[0], server_resume_log[1]);
    assert_eq!(client_resume_log[1], server_resume_log[2]);
    assert_eq!(client_resume_log[2], server_resume_log[3]);
    assert_eq!(client_resume_log[3], server_resume_log[4]);
    assert_eq!(client_resume_log[4], server_resume_log[5]);
}

#[ignore = "needs to be fixed"]
#[tokio::test]
async fn servered_write_for_server_appdata() {
    let (mut client, mut server) = make_pair(KeyType::Rsa).await;
    do_handshake(&mut client, &mut server).await;

    server.writer().write_all(b"01234567890123456789").unwrap();
    server.writer().write_all(b"01234567890123456789").unwrap();
    {
        let mut pipe = ClientSession::new(&mut client);
        let wrlen = server.write_tls(&mut pipe).unwrap();
        assert_eq!(84, wrlen);
        assert_eq!(pipe.writevs, vec![vec![42, 42]]);
    }
    check_read(
        &mut client.reader(),
        b"0123456789012345678901234567890123456789",
    );
}

#[ignore = "needs to be fixed"]
#[tokio::test]
async fn servered_write_for_client_appdata() {
    let (mut client, mut server) = make_pair(KeyType::Rsa).await;
    do_handshake(&mut client, &mut server).await;

    client
        .write_all_plaintext(b"01234567890123456789")
        .await
        .unwrap();
    client
        .write_all_plaintext(b"01234567890123456789")
        .await
        .unwrap();
    {
        let mut pipe = ServerSession::new(&mut server);
        let wrlen = client.write_tls(&mut pipe).unwrap();
        assert_eq!(84, wrlen);
        assert_eq!(pipe.writevs, vec![vec![42, 42]]);
    }
    check_read(
        &mut server.reader(),
        b"0123456789012345678901234567890123456789",
    );
}

#[ignore = "needs to be fixed"]
#[tokio::test]
async fn servered_write_for_server_handshake_with_half_rtt_data() {
    let mut server_config = make_server_config(KeyType::Rsa);
    server_config.send_half_rtt_data = true;
    let (mut client, mut server) =
        make_pair_for_configs(make_client_config_with_auth(KeyType::Rsa), server_config).await;

    server.writer().write_all(b"01234567890123456789").unwrap();
    server.writer().write_all(b"0123456789").unwrap();

    send(&mut client, &mut server);
    server.process_new_packets().unwrap();
    {
        let mut pipe = ClientSession::new(&mut client);
        let wrlen = server.write_tls(&mut pipe).unwrap();
        // don't assert exact sizes here, to avoid a brittle test
        assert!(wrlen > 4000); // its pretty big (contains cert chain)
        assert_eq!(pipe.writevs.len(), 1); // only one writev
        assert_eq!(pipe.writevs[0].len(), 8); // at least a server hello/ccs/cert/serverkx/0.5rtt data
    }

    client.process_new_packets().await.unwrap();
    send(&mut client, &mut server);
    server.process_new_packets().unwrap();
    {
        let mut pipe = ClientSession::new(&mut client);
        let wrlen = server.write_tls(&mut pipe).unwrap();
        assert_eq!(wrlen, 103);
        assert_eq!(pipe.writevs, vec![vec![103]]);
    }

    assert!(!server.is_handshaking());
    assert!(!client.is_handshaking());
    check_read(&mut client.reader(), b"012345678901234567890123456789");
}

async fn check_half_rtt_does_not_work(server_config: ServerConfig) {
    let (mut client, mut server) =
        make_pair_for_configs(make_client_config_with_auth(KeyType::Rsa), server_config).await;

    server.writer().write_all(b"01234567890123456789").unwrap();
    server.writer().write_all(b"0123456789").unwrap();

    send(&mut client, &mut server);
    server.process_new_packets().unwrap();
    {
        let mut pipe = ClientSession::new(&mut client);
        let wrlen = server.write_tls(&mut pipe).unwrap();
        // don't assert exact sizes here, to avoid a brittle test
        assert!(wrlen > 4000); // its pretty big (contains cert chain)
        assert_eq!(pipe.writevs.len(), 1); // only one writev
        assert!(pipe.writevs[0].len() >= 6); // at least a server hello/ccs/cert/serverkx data
    }

    // client second flight
    client.process_new_packets().await.unwrap();
    send(&mut client, &mut server);

    // when client auth is enabled, we don't sent 0.5-rtt data, as we'd be sending
    // it to an unauthenticated peer. so it happens here, in the server's second
    // flight (42 and 32 are lengths of appdata sent above).
    server.process_new_packets().unwrap();
    {
        let mut pipe = ClientSession::new(&mut client);
        let wrlen = server.write_tls(&mut pipe).unwrap();
        assert_eq!(wrlen, 177);
        assert_eq!(pipe.writevs, vec![vec![103, 42, 32]]);
    }

    assert!(!server.is_handshaking());
    assert!(!client.is_handshaking());
    check_read(&mut client.reader(), b"012345678901234567890123456789");
}

#[ignore = "needs to be fixed"]
#[tokio::test]
async fn servered_write_for_server_handshake_no_half_rtt_with_client_auth() {
    let mut server_config = make_server_config_with_mandatory_client_auth(KeyType::Rsa);
    server_config.send_half_rtt_data = true; // ask even though it will be ignored
    check_half_rtt_does_not_work(server_config).await;
}

#[ignore = "needs to be fixed"]
#[tokio::test]
async fn servered_write_for_server_handshake_no_half_rtt_by_default() {
    let server_config = make_server_config(KeyType::Rsa);
    assert!(!server_config.send_half_rtt_data);
    check_half_rtt_does_not_work(server_config).await;
}

#[ignore = "needs to be fixed"]
#[tokio::test]
async fn servered_write_for_client_handshake() {
    let (mut client, mut server) = make_pair(KeyType::Rsa).await;

    client
        .write_all_plaintext(b"01234567890123456789")
        .await
        .unwrap();
    client.write_all_plaintext(b"0123456789").await.unwrap();
    {
        let mut pipe = ServerSession::new(&mut server);
        let wrlen = client.write_tls(&mut pipe).unwrap();
        // don't assert exact sizes here, to avoid a brittle test
        assert!(wrlen > 200); // just the client hello
        assert_eq!(pipe.writevs.len(), 1); // only one writev
        assert!(pipe.writevs[0].len() == 1); // only a client hello
    }

    receive(&mut server, &mut client);
    client.process_new_packets().await.unwrap();

    {
        let mut pipe = ServerSession::new(&mut server);
        let wrlen = client.write_tls(&mut pipe).unwrap();
        assert_eq!(wrlen, 154);
        // CCS, finished, then two application datas
        assert_eq!(pipe.writevs, vec![vec![6, 74, 42, 32]]);
    }

    assert!(!server.is_handshaking());
    assert!(!client.is_handshaking());
    check_read(&mut server.reader(), b"012345678901234567890123456789");
}

#[ignore = "needs to be fixed"]
#[tokio::test]
async fn servered_write_with_slow_client() {
    let (mut client, mut server) = make_pair(KeyType::Rsa).await;

    client.set_buffer_limit(Some(32));

    do_handshake(&mut client, &mut server).await;
    server.writer().write_all(b"01234567890123456789").unwrap();

    {
        let mut pipe = ClientSession::new(&mut client);
        pipe.short_writes = true;
        let wrlen = server.write_tls(&mut pipe).unwrap()
            + server.write_tls(&mut pipe).unwrap()
            + server.write_tls(&mut pipe).unwrap()
            + server.write_tls(&mut pipe).unwrap()
            + server.write_tls(&mut pipe).unwrap()
            + server.write_tls(&mut pipe).unwrap();
        assert_eq!(42, wrlen);
        assert_eq!(
            pipe.writevs,
            vec![vec![21], vec![10], vec![5], vec![3], vec![3]]
        );
    }
    check_read(&mut client.reader(), b"01234567890123456789");
}

struct ServerStorage {
    storage: Arc<dyn rustls::server::StoresServerSessions>,
    put_count: AtomicUsize,
    get_count: AtomicUsize,
    take_count: AtomicUsize,
}

impl ServerStorage {
    fn new() -> Self {
        ServerStorage {
            storage: rustls::server::ServerSessionMemoryCache::new(1024),
            put_count: AtomicUsize::new(0),
            get_count: AtomicUsize::new(0),
            take_count: AtomicUsize::new(0),
        }
    }

    fn puts(&self) -> usize {
        self.put_count.load(Ordering::SeqCst)
    }
    fn gets(&self) -> usize {
        self.get_count.load(Ordering::SeqCst)
    }
    fn takes(&self) -> usize {
        self.take_count.load(Ordering::SeqCst)
    }
}

impl fmt::Debug for ServerStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(put: {:?}, get: {:?}, take: {:?})",
            self.put_count, self.get_count, self.take_count
        )
    }
}

impl rustls::server::StoresServerSessions for ServerStorage {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.put_count.fetch_add(1, Ordering::SeqCst);
        self.storage.put(key, value)
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.get_count.fetch_add(1, Ordering::SeqCst);
        self.storage.get(key)
    }

    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.take_count.fetch_add(1, Ordering::SeqCst);
        self.storage.take(key)
    }

    fn can_cache(&self) -> bool {
        true
    }
}

struct ClientStorage {
    storage: Arc<dyn tls_client::client::StoresClientSessions>,
    put_count: AtomicUsize,
    get_count: AtomicUsize,
    last_put_key: Mutex<Option<Vec<u8>>>,
}

impl ClientStorage {
    fn new() -> Self {
        ClientStorage {
            storage: tls_client::client::ClientSessionMemoryCache::new(1024),
            put_count: AtomicUsize::new(0),
            get_count: AtomicUsize::new(0),
            last_put_key: Mutex::new(None),
        }
    }

    fn puts(&self) -> usize {
        self.put_count.load(Ordering::SeqCst)
    }
    fn gets(&self) -> usize {
        self.get_count.load(Ordering::SeqCst)
    }
}

impl fmt::Debug for ClientStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(puts: {:?}, gets: {:?} )",
            self.put_count, self.get_count
        )
    }
}

impl tls_client::client::StoresClientSessions for ClientStorage {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.put_count.fetch_add(1, Ordering::SeqCst);
        *self.last_put_key.lock().unwrap() = Some(key.clone());
        self.storage.put(key, value)
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.get_count.fetch_add(1, Ordering::SeqCst);
        self.storage.get(key)
    }
}

#[ignore = "needs to be fixed"]
#[tokio::test]
async fn tls13_stateful_resumption() {
    let kt = KeyType::Rsa;
    let client_config = make_client_config_with_versions(kt, &[&tls_client::version::TLS13]);
    let client_config = Arc::new(client_config);

    let mut server_config = make_server_config(kt);
    let storage = Arc::new(ServerStorage::new());
    server_config.session_storage = storage.clone();
    let server_config = Arc::new(server_config);

    // full handshake
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config).await;
    let (full_c2s, full_s2c) = do_handshake(&mut client, &mut server).await;
    assert_eq!(storage.puts(), 1);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 0);
    assert_eq!(client.peer_certificates().map(|certs| certs.len()), Some(3));

    // resumed
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config).await;
    let (resume_c2s, resume_s2c) = do_handshake(&mut client, &mut server).await;
    assert!(resume_c2s > full_c2s);
    assert!(resume_s2c < full_s2c);
    assert_eq!(storage.puts(), 2);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 1);
    assert_eq!(client.peer_certificates().map(|certs| certs.len()), Some(3));

    // resumed again
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config).await;
    let (resume2_c2s, resume2_s2c) = do_handshake(&mut client, &mut server).await;
    assert_eq!(resume_s2c, resume2_s2c);
    assert_eq!(resume_c2s, resume2_c2s);
    assert_eq!(storage.puts(), 3);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 2);
    assert_eq!(client.peer_certificates().map(|certs| certs.len()), Some(3));
}

#[ignore = "needs to be fixed"]
#[tokio::test]
async fn tls13_stateless_resumption() {
    let kt = KeyType::Rsa;
    let client_config = make_client_config_with_versions(kt, &[&tls_client::version::TLS13]);
    let client_config = Arc::new(client_config);

    let mut server_config = make_server_config(kt);
    server_config.ticketer = rustls::Ticketer::new().unwrap();
    let storage = Arc::new(ServerStorage::new());
    server_config.session_storage = storage.clone();
    let server_config = Arc::new(server_config);

    // full handshake
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config).await;
    let (full_c2s, full_s2c) = do_handshake(&mut client, &mut server).await;
    assert_eq!(storage.puts(), 0);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 0);
    assert_eq!(client.peer_certificates().map(|certs| certs.len()), Some(3));

    // resumed
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config).await;
    let (resume_c2s, resume_s2c) = do_handshake(&mut client, &mut server).await;
    assert!(resume_c2s > full_c2s);
    assert!(resume_s2c < full_s2c);
    assert_eq!(storage.puts(), 0);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 0);
    assert_eq!(client.peer_certificates().map(|certs| certs.len()), Some(3));

    // resumed again
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config).await;
    let (resume2_c2s, resume2_s2c) = do_handshake(&mut client, &mut server).await;
    assert_eq!(resume_s2c, resume2_s2c);
    assert_eq!(resume_c2s, resume2_c2s);
    assert_eq!(storage.puts(), 0);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 0);
    assert_eq!(client.peer_certificates().map(|certs| certs.len()), Some(3));
}

// #[tokio::test]
// async fn early_data_not_available() {
//     let (mut client, _) = make_pair(KeyType::Rsa).await;
//     assert!(client.early_data().is_none());
// }

// fn early_data_configs() -> (Arc<ClientConfig>, Arc<ServerConfig>) {
//     let kt = KeyType::Rsa;
//     let mut client_config = make_client_config(kt);
//     client_config.enable_early_data = true;
//     client_config.session_storage = Arc::new(ClientStorage::new());

//     let mut server_config = make_server_config(kt);
//     server_config.max_early_data_size = 1234;
//     (Arc::new(client_config), Arc::new(server_config))
// }

// #[tokio::test]
// async fn early_data_is_available_on_resumption() {
//     let (client_config, server_config) = early_data_configs();

//     let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config).await;
//     do_handshake(&mut client, &mut server).await;

//     let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config).await;
//     assert!(client.early_data().is_some());
//     assert_eq!(client.early_data().unwrap().bytes_left(), 1234);
//     client.early_data().unwrap().flush().unwrap();
//     assert_eq!(client.early_data().unwrap().write(b"hello").unwrap(), 5);
//     do_handshake(&mut client, &mut server).await;

//     let mut received_early_data = [0u8; 5];
//     assert_eq!(
//         server
//             .early_data()
//             .expect("early_data didn't happen")
//             .read(&mut received_early_data)
//             .expect("early_data failed unexpectedly"),
//         5
//     );
//     assert_eq!(&received_early_data[..], b"hello");
// }

// #[tokio::test]
// async fn early_data_can_be_rejected_by_server() {
//     let (client_config, server_config) = early_data_configs();

//     let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config).await;
//     do_handshake(&mut client, &mut server).await;

//     let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config).await;
//     assert!(client.early_data().is_some());
//     assert_eq!(client.early_data().unwrap().bytes_left(), 1234);
//     client.early_data().unwrap().flush().unwrap();
//     assert_eq!(client.early_data().unwrap().write(b"hello").unwrap(), 5);
//     server.reject_early_data();
//     do_handshake(&mut client, &mut server).await;

//     assert_eq!(client.is_early_data_accepted(), false);
// }

#[tokio::test]
async fn test_client_does_not_offer_sha1() {
    use tls_client::internal::msgs::{
        codec::Reader,
        enums::HandshakeType,
        handshake::HandshakePayload,
        message::{MessagePayload, OpaqueMessage},
    };

    for kt in ALL_KEY_TYPES.iter() {
        for version in tls_client::ALL_VERSIONS {
            let client_config = make_client_config_with_versions(*kt, &[version]);
            let (mut client, _) =
                make_pair_for_configs(client_config, make_server_config(*kt)).await;

            assert!(client.wants_write());
            let mut buf = [0u8; 262144];
            let sz = client.write_tls(&mut buf.as_mut()).unwrap();
            let msg = OpaqueMessage::read(&mut Reader::init(&buf[..sz])).unwrap();
            let msg = Message::try_from(msg.into_plain_message()).unwrap();
            assert!(msg.is_handshake_type(HandshakeType::ClientHello));

            let client_hello = match msg.payload {
                MessagePayload::Handshake(hs) => match hs.payload {
                    HandshakePayload::ClientHello(ch) => ch,
                    _ => unreachable!(),
                },
                _ => unreachable!(),
            };

            let sigalgs = client_hello.get_sigalgs_extension().unwrap();
            assert!(
                !sigalgs.contains(&SignatureScheme::RSA_PKCS1_SHA1),
                "sha1 unexpectedly offered"
            );
        }
    }
}

#[ignore = "needs to be fixed"]
#[tokio::test]
async fn test_client_config_keyshare() {
    let client_config =
        make_client_config_with_kx_groups(KeyType::Rsa, &[&tls_client::kx_group::SECP384R1]);
    let server_config =
        make_server_config_with_kx_groups(KeyType::Rsa, &[&rustls::kx_group::SECP384R1]);
    let (mut client, mut server) = make_pair_for_configs(client_config, server_config).await;
    do_handshake_until_error(&mut client, &mut server)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_client_config_keyshare_mismatch() {
    let client_config =
        make_client_config_with_kx_groups(KeyType::Rsa, &[&tls_client::kx_group::SECP384R1]);
    let server_config =
        make_server_config_with_kx_groups(KeyType::Rsa, &[&rustls::kx_group::X25519]);
    let (mut client, mut server) = make_pair_for_configs(client_config, server_config).await;
    assert!(do_handshake_until_error(&mut client, &mut server)
        .await
        .is_err());
}

#[ignore = "needs to be fixed"]
#[tokio::test]
async fn test_client_sends_helloretryrequest() {
    // client sends a secp384r1 key share
    let mut client_config = make_client_config_with_kx_groups(
        KeyType::Rsa,
        &[
            &tls_client::kx_group::SECP384R1,
            &tls_client::kx_group::X25519,
        ],
    );

    let storage = Arc::new(ClientStorage::new());
    client_config.session_storage = storage.clone();

    // but server only accepts x25519, so a HRR is required
    let server_config =
        make_server_config_with_kx_groups(KeyType::Rsa, &[&rustls::kx_group::X25519]);

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config).await;

    // client sends hello
    {
        let mut pipe = ServerSession::new(&mut server);
        let wrlen = client.write_tls(&mut pipe).unwrap();
        assert!(wrlen > 200);
        assert_eq!(pipe.writevs.len(), 1);
        assert!(pipe.writevs[0].len() == 1);
    }

    // server sends HRR
    {
        let mut pipe = ClientSession::new(&mut client);
        let wrlen = server.write_tls(&mut pipe).unwrap();
        assert!(wrlen < 100); // just the hello retry request
        assert_eq!(pipe.writevs.len(), 1); // only one writev
        assert!(pipe.writevs[0].len() == 2); // hello retry request and CCS
    }

    // client sends fixed hello
    {
        let mut pipe = ServerSession::new(&mut server);
        let wrlen = client.write_tls(&mut pipe).unwrap();
        assert!(wrlen > 200); // just the client hello retry
        assert_eq!(pipe.writevs.len(), 1); // only one writev
        assert!(pipe.writevs[0].len() == 2); // only a CCS & client hello retry
    }

    // server completes handshake
    {
        let mut pipe = ClientSession::new(&mut client);
        let wrlen = server.write_tls(&mut pipe).unwrap();
        assert!(wrlen > 200);
        assert_eq!(pipe.writevs.len(), 1);
        assert!(pipe.writevs[0].len() == 5); // server hello / encrypted exts / cert / cert-verify / finished
    }

    do_handshake_until_error(&mut client, &mut server)
        .await
        .unwrap();

    // client only did two storage queries: one for a session, another for a kx type
    assert_eq!(storage.gets(), 2);
    assert_eq!(storage.puts(), 2);
}

#[ignore = "needs to be fixed"]
#[tokio::test]
async fn test_client_attempts_to_use_unsupported_kx_group() {
    // common to both client configs
    let shared_storage = Arc::new(ClientStorage::new());

    // first, client sends a x25519 and server agrees. x25519 is inserted
    //   into kx group cache.
    let mut client_config_1 =
        make_client_config_with_kx_groups(KeyType::Rsa, &[&tls_client::kx_group::X25519]);
    client_config_1.session_storage = shared_storage.clone();

    // second, client only supports secp-384 and so kx group cache
    //   contains an unusable value.
    let mut client_config_2 =
        make_client_config_with_kx_groups(KeyType::Rsa, &[&tls_client::kx_group::SECP384R1]);
    client_config_2.session_storage = shared_storage;

    let server_config = make_server_config(KeyType::Rsa);

    // first handshake
    let (mut client_1, mut server) =
        make_pair_for_configs(client_config_1, server_config.clone()).await;
    do_handshake_until_error(&mut client_1, &mut server)
        .await
        .unwrap();

    // second handshake
    let (mut client_2, mut server) = make_pair_for_configs(client_config_2, server_config).await;
    do_handshake_until_error(&mut client_2, &mut server)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_client_mtu_reduction() {
    struct CollectWrites {
        writevs: Vec<Vec<usize>>,
    }

    impl io::Write for CollectWrites {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            panic!()
        }
        fn flush(&mut self) -> io::Result<()> {
            panic!()
        }
        fn write_vectored(&mut self, b: &[io::IoSlice<'_>]) -> io::Result<usize> {
            let writes = b.iter().map(|slice| slice.len()).collect::<Vec<usize>>();
            let len = writes.iter().sum();
            self.writevs.push(writes);
            Ok(len)
        }
    }

    fn collect_write_lengths(client: &mut ClientConnection) -> Vec<usize> {
        let mut collector = CollectWrites { writevs: vec![] };

        client.write_tls(&mut collector).unwrap();
        assert_eq!(collector.writevs.len(), 1);
        collector.writevs[0].clone()
    }

    for kt in ALL_KEY_TYPES.iter() {
        let mut client_config = make_client_config(*kt);
        client_config.max_fragment_size = Some(64);
        let mut client = ClientConnection::new(
            Arc::new(client_config),
            Box::new(RustCryptoBackend::new()),
            dns_name("localhost"),
        )
        .unwrap();
        client.start().await.unwrap();
        let writes = collect_write_lengths(&mut client);
        println!("writes at mtu=64: {:?}", writes);
        assert!(writes.iter().all(|x| *x <= 64));
        assert!(writes.len() > 1);
    }
}

#[ignore = "needs to be fixed"]
#[tokio::test]
async fn test_server_mtu_reduction() {
    let mut server_config = make_server_config(KeyType::Rsa);
    server_config.max_fragment_size = Some(64);
    server_config.send_half_rtt_data = true;
    let (mut client, mut server) =
        make_pair_for_configs(make_client_config(KeyType::Rsa), server_config).await;

    let big_data = [0u8; 2048];
    server.writer().write_all(&big_data).unwrap();

    let encryption_overhead = 20; // FIXME: see issue #991

    send(&mut client, &mut server);
    server.process_new_packets().unwrap();
    {
        let mut pipe = ClientSession::new(&mut client);
        server.write_tls(&mut pipe).unwrap();

        assert_eq!(pipe.writevs.len(), 1);
        assert!(pipe.writevs[0]
            .iter()
            .all(|x| *x <= 64 + encryption_overhead));
    }

    client.process_new_packets().await.unwrap();
    send(&mut client, &mut server);
    server.process_new_packets().unwrap();
    {
        let mut pipe = ClientSession::new(&mut client);
        server.write_tls(&mut pipe).unwrap();
        assert_eq!(pipe.writevs.len(), 1);
        assert!(pipe.writevs[0]
            .iter()
            .all(|x| *x <= 64 + encryption_overhead));
    }

    client.process_new_packets().await.unwrap();
    check_read(&mut client.reader(), &big_data);
}

async fn check_client_max_fragment_size(size: usize) -> Option<Error> {
    let mut client_config = make_client_config(KeyType::Ed25519);
    client_config.max_fragment_size = Some(size);
    ClientConnection::new(
        Arc::new(client_config),
        Box::new(RustCryptoBackend::new()),
        dns_name("localhost"),
    )
    .err()
}

#[tokio::test]
async fn bad_client_max_fragment_sizes() {
    assert_eq!(
        check_client_max_fragment_size(31).await,
        Some(Error::BadMaxFragmentSize)
    );
    assert_eq!(check_client_max_fragment_size(32).await, None);
    assert_eq!(check_client_max_fragment_size(64).await, None);
    assert_eq!(check_client_max_fragment_size(1460).await, None);
    assert_eq!(check_client_max_fragment_size(0x4000).await, None);
    assert_eq!(check_client_max_fragment_size(0x4005).await, None);
    assert_eq!(
        check_client_max_fragment_size(0x4006).await,
        Some(Error::BadMaxFragmentSize)
    );
    assert_eq!(
        check_client_max_fragment_size(0xffff).await,
        Some(Error::BadMaxFragmentSize)
    );
}

fn assert_lt(left: usize, right: usize) {
    if left >= right {
        panic!("expected {} < {}", left, right);
    }
}

#[test]
fn connection_types_are_not_huge() {
    // Arbitrary sizes
    assert_lt(mem::size_of::<ClientConnection>(), 1600);
}

use tls_client::internal::msgs::message::{Message, MessagePayload};

#[ignore = "needs to be fixed"]
#[tokio::test]
async fn test_client_rejects_illegal_tls13_ccs() {
    fn corrupt_ccs(msg: &mut Message) -> Altered {
        if let MessagePayload::ChangeCipherSpec(_) = &mut msg.payload {
            println!("seen CCS {:?}", msg);
            return Altered::Raw(vec![0x14, 0x03, 0x03, 0x00, 0x02, 0x01, 0x02]);
        }
        Altered::InPlace
    }

    let (mut client, mut server) = make_pair(KeyType::Rsa).await;
    send(&mut client, &mut server);
    server.process_new_packets().unwrap();

    let (mut server, mut client) = (server.into(), client);

    receive_altered(&mut server, corrupt_ccs, &mut client);
    assert_eq!(
        client.process_new_packets().await,
        Err(Error::PeerMisbehavedError(
            "illegal middlebox CCS received".into()
        ))
    );
}

/// https://github.com/rustls/rustls/issues/797
#[ignore = "needs to be fixed"]
#[cfg(feature = "tls12")]
#[tokio::test]
async fn test_client_tls12_no_resume_after_server_downgrade() {
    let mut client_config = common::make_client_config(KeyType::Ed25519);
    let client_storage = Arc::new(ClientStorage::new());
    client_config.session_storage = client_storage.clone();
    let client_config = Arc::new(client_config);

    let server_config_1 = Arc::new(common::finish_server_config(
        KeyType::Ed25519,
        ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap(),
    ));

    let mut server_config_2 = common::finish_server_config(
        KeyType::Ed25519,
        ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap(),
    );
    server_config_2.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});

    dbg!("handshake 1");
    let mut client_1 = ClientConnection::new(
        client_config.clone(),
        Box::new(RustCryptoBackend::new()),
        "localhost".try_into().unwrap(),
    )
    .unwrap();
    client_1.start().await.unwrap();
    let mut server_1 = ServerConnection::new(server_config_1).unwrap();
    common::do_handshake(&mut client_1, &mut server_1).await;
    assert_eq!(client_storage.puts(), 2);

    dbg!("handshake 2");
    let mut client_2 = ClientConnection::new(
        client_config,
        Box::new(RustCryptoBackend::new()),
        "localhost".try_into().unwrap(),
    )
    .unwrap();
    client_2.start().await.unwrap();
    let mut server_2 = ServerConnection::new(Arc::new(server_config_2)).unwrap();
    common::do_handshake(&mut client_2, &mut server_2).await;
    assert_eq!(client_storage.puts(), 2);
}

#[derive(Default, Debug)]
struct LogCounts {
    trace: usize,
    debug: usize,
    info: usize,
    warn: usize,
    error: usize,
}

impl LogCounts {
    fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    fn add(&mut self, level: log::Level) {
        match level {
            log::Level::Trace => self.trace += 1,
            log::Level::Debug => self.debug += 1,
            log::Level::Info => self.info += 1,
            log::Level::Warn => self.warn += 1,
            log::Level::Error => self.error += 1,
        }
    }
}

thread_local!(static COUNTS: RefCell<LogCounts> = RefCell::new(LogCounts::new()));

struct CountingLogger;

static LOGGER: CountingLogger = CountingLogger;

impl CountingLogger {
    fn install() {
        log::set_logger(&LOGGER).unwrap();
        log::set_max_level(log::LevelFilter::Trace);
    }

    fn reset() {
        COUNTS.with(|c| {
            c.borrow_mut().reset();
        });
    }
}

impl log::Log for CountingLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        println!("logging at {:?}: {:?}", record.level(), record.args());

        COUNTS.with(|c| {
            c.borrow_mut().add(record.level());
        });
    }

    fn flush(&self) {}
}

#[tokio::test]
async fn test_no_warning_logging_during_successful_sessions() {
    CountingLogger::install();
    CountingLogger::reset();

    for kt in ALL_KEY_TYPES.iter() {
        for version in tls_client::ALL_VERSIONS {
            let client_config = make_client_config_with_versions(*kt, &[version]);
            let (mut client, mut server) =
                make_pair_for_configs(client_config, make_server_config(*kt)).await;
            do_handshake(&mut client, &mut server).await;
        }
    }

    if cfg!(feature = "logging") {
        COUNTS.with(|c| {
            println!("After tests: {:?}", c.borrow());
            assert_eq!(c.borrow().warn, 0);
            assert_eq!(c.borrow().error, 0);
            assert_eq!(c.borrow().info, 0);
            assert!(c.borrow().trace > 0);
            assert!(c.borrow().debug > 0);
        });
    } else {
        COUNTS.with(|c| {
            println!("After tests: {:?}", c.borrow());
            assert_eq!(c.borrow().warn, 0);
            assert_eq!(c.borrow().error, 0);
            assert_eq!(c.borrow().info, 0);
            assert_eq!(c.borrow().trace, 0);
            assert_eq!(c.borrow().debug, 0);
        });
    }
}
