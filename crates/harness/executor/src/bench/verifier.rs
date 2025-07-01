use anyhow::Result;

use harness_core::bench::Bench;
use tls_core::verify::WebPkiVerifier;
use tlsn::{
    config::ProtocolConfigValidator,
    verifier::{Verifier, VerifierConfig},
};
use tlsn_core::{CryptoProvider, VerifyConfig};
use tlsn_server_fixture_certs::CA_CERT_DER;

use crate::{IoProvider, bench::RECV_PADDING};

pub async fn bench_verifier(provider: &IoProvider, config: &Bench) -> Result<()> {
    let mut builder = ProtocolConfigValidator::builder();
    builder
        .max_sent_data(config.upload_size)
        .max_recv_data(config.download_size + RECV_PADDING);

    let protocol_config = builder.build()?;

    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let crypto_provider = CryptoProvider {
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    };

    let verifier = Verifier::new(
        VerifierConfig::builder()
            .protocol_config_validator(protocol_config)
            .crypto_provider(crypto_provider)
            .build()?,
    );

    let verifier = verifier.setup(provider.provide_proto_io().await?).await?;
    let mut verifier = verifier.run().await?;
    verifier.verify(&VerifyConfig::default()).await?;
    verifier.close().await?;

    Ok(())
}
