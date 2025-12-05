use anyhow::Result;

use futures::TryFutureExt;
use harness_core::bench::Bench;
use tlsn::{
    config::verifier::VerifierConfig,
    verifier::{Verifier, VerifierError},
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

    let mut prover_io = provider.provide_proto_io().await?;
    let (mpc_conn, verifier) = verifier.commit_with(&mut prover_io).await?;

    let mpc_fut = mpc_conn.into_future(prover_io).map_err(VerifierError::from);
    let verifier = async {
        let verifier = verifier.accept().await?.run().await?;
        let (_, verifier) = verifier.verify().await?.accept().await?;
        verifier.close().await
    };

    futures::try_join!(mpc_fut, verifier);
    Ok(())
}
