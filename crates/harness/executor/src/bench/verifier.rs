use anyhow::Result;

use harness_core::bench::Bench;
use tlsn::{
    Session,
    config::{tls_commit::TlsCommitRequest, verifier::VerifierConfig},
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

    let verifier = match verifier.request().clone() {
        TlsCommitRequest::Mpc(config) => verifier.accept(config).await?.run().await?,
        TlsCommitRequest::Proxy(config) => {
            let server_io = provider.provide_server_io().await?;
            verifier.accept(config).await?.run(server_io).await?
        }
        _ => panic!("unsupported protocol mode"),
    };

    let (_, verifier) = verifier.verify().await?.accept().await?;
    verifier.close().await?;
    handle.close();

    Ok(())
}
