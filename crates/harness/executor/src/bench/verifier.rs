use anyhow::Result;

use harness_core::bench::Bench;
use tlsn::{
    Session,
    config::{tls_commit::TlsCommitProtocolConfig, verifier::VerifierConfig},
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_server_fixture_certs::CA_CERT_DER;

use crate::{IoProvider, spawn};

pub async fn bench_verifier(provider: &IoProvider, _config: &Bench) -> Result<()> {
    let io = provider.provide_proto_io().await?;
    let mut session = Session::new(io);

    let verifier = session.new_verifier(
        VerifierConfig::builder()
            .root_store(RootCertStore {
                roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
            })
            .build()?,
    )?;

    let (session, handle) = session.split();

    _ = spawn(session);

    let verifier = verifier.commit().await?;

    let is_proxy = matches!(
        verifier.request().protocol(),
        TlsCommitProtocolConfig::Proxy(_)
    );

    let verifier = verifier.accept().await?;
    let verifier = if is_proxy {
        let server_io = provider.provide_server_io().await?;
        verifier.run_proxy(server_io).await?
    } else {
        verifier.run_mpc().await?
    };

    let (_, verifier) = verifier.verify().await?.accept().await?;
    verifier.close().await?;
    handle.close();

    Ok(())
}
