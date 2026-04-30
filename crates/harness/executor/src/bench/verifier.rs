use anyhow::Result;

use harness_core::bench::Bench;
use tlsn::{
    Session,
    config::verifier::VerifierConfig,
    verifier::VerifierCommitAccepted,
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

    let verifier = match verifier.accept().await? {
        VerifierCommitAccepted::Mpc(verifier) => verifier.run().await?,
        VerifierCommitAccepted::Proxy(verifier) => {
            let server_io = provider.provide_server_io().await?;
            verifier.run(server_io).await?
        }
    };

    let (_, verifier) = verifier.verify().await?.accept().await?;
    verifier.close().await?;
    handle.close();

    Ok(())
}
