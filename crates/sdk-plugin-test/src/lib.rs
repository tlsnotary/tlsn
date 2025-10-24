use hyper_util::rt::TokioIo;
use tlsn_pdk::{entry, prover::Prover, verifier::Verifier};
use tlsn_plugin_core::{
    ProverPluginConfig, ProverPluginOutput, VerifierPluginConfig, VerifierPluginOutput,
};
use tokio_util::compat::FuturesAsyncReadCompatExt;

//entry!(prove);

async fn prove(cfg: ProverPluginConfig) -> Result<ProverPluginOutput, String> {
    let mut prover = Prover::new(cfg.prover_config()).setup().await.unwrap();

    let (mut conn, prover_fut) = prover.connect().await.unwrap();

    let prover = if cfg.is_http {
        // MPC-TLS Handshake.
        let io = TokioIo::new(conn.compat());

        let (mut request_sender, handshake) =
            hyper::client::conn::http1::handshake(io).await.unwrap();

        let send_req_fut = request_sender.send_request(cfg.http_request());

        // Ignore the server response here, since it can also be obtained from
        // the transcript.
        let (prover, _, _) = futures::join!(prover_fut, send_req_fut, handshake,);
        prover
    } else {
        unimplemented!("non-http proving not currently supported ");
    };

    let mut prover = prover.unwrap();

    let config = cfg.prove_config(prover.transcript());

    let output = prover.prove(&config).await.unwrap();

    let transcript = prover.transcript().clone();

    prover.close().await.unwrap();

    let out = cfg.output(transcript, output);

    Ok(out)
}

async fn verify(cfg: VerifierPluginConfig) -> Result<Vec<u8>, String> {
    let config = cfg.verifier_config();

    let mut verifier = Verifier::new(config)
        .setup()
        .await
        .unwrap()
        .run()
        .await
        .unwrap();

    //let output = verifier.verify(&VerifyConfig::default()).await.unwrap();

    verifier.close().await.unwrap();

    //let out = cfg.output(output);

    Ok(vec![])
}
