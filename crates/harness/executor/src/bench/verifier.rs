use anyhow::Result;

use harness_core::bench::Bench;
use tlsn::{
    config::verifier::VerifierConfig,
    verifier::Verifier,
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_server_fixture_certs::CA_CERT_DER;

use crate::IoProvider;

pub async fn bench_verifier(provider: &IoProvider, _config: &Bench) -> Result<()> {
    let verifier = Verifier::new(
        VerifierConfig::builder()
            .root_store(RootCertStore {
                roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
            })
            .build()?,
    );

    let verifier = verifier
        .commit(provider.provide_proto_io().await?)
        .await?
        .accept()
        .await?
        .run()
        .await?;
    let (_, verifier) = verifier.verify().await?.accept().await?;
    verifier.close().await?;

    Ok(())
}
