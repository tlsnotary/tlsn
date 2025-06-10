use anyhow::anyhow;
use extism_pdk::{debug, info, plugin_fn, FnResult, FromBytes, Json, ToBytes};
use serde::{Deserialize, Serialize};
use tlsn_core::VerifierOutput;

const SERVER_DOMAIN: &str = "raw.githubusercontent.com";

#[derive(Serialize, Deserialize, FromBytes, ToBytes, Debug, Default)]
#[encoding(Json)]
struct PluginVerifierConfig {
    /// Maximum number of bytes that can be sent.
    max_sent_data: Option<usize>,
     /// Maximum number of application data records that can be sent.
    max_sent_records: Option<usize>,
    /// Maximum number of bytes that can be received.
    max_recv_data: Option<usize>,
    /// Maximum number of application data records that can be received.
    max_recv_records_online: Option<usize>,
}

#[plugin_fn]
pub fn config() -> FnResult<PluginVerifierConfig> {
    debug!("Composing verifier configuration...");
    Ok(PluginVerifierConfig::default())
}

#[plugin_fn]
pub fn verify(output: Json<VerifierOutput>) -> FnResult<()> {
    debug!("Starting verification...");
    let VerifierOutput {
        server_name,
        transcript,
        ..
    } = output.into_inner();

    let transcript = transcript.
        ok_or(anyhow!("prover should have revealed transcript data"))?;
    let server_name = server_name.
        ok_or(anyhow!("prover should have revealed server name"))?;

    // Check sent data: check host.
    debug!("Starting sent data verification...");
    let sent = transcript.sent_unsafe().to_vec();
    let sent_data = String::from_utf8(sent.clone())
        .map_err(|err| anyhow!("Verifier expected sent data: {err}"))?;
    sent_data
        .find(SERVER_DOMAIN)
        .ok_or(anyhow!("Verification failed: Expected host {}", SERVER_DOMAIN))?;

    // Check received data: check json and version number.
    debug!("Starting received data verification...");
    let received = transcript.received_unsafe().to_vec();
    let response = String::from_utf8(received.clone())
        .map_err(|err| anyhow!("Verifier expected received data: {err}"))?;

    response
        .find("123 Elm Street")
        .ok_or(anyhow!("Verification failed: missing data in received data"))?;

    // Check Session info: server name.
    if server_name.as_str() != SERVER_DOMAIN {
        return Err(anyhow!("Verification failed: server name mismatches").into());
    }

    let sent_string = bytes_to_redacted_string(&sent)?;
    let received_string = bytes_to_redacted_string(&received)?;

    info!("Successfully verified {}", SERVER_DOMAIN);
    info!("Verified sent data:\n{}", sent_string);
    info!("Verified received data:\n{received_string}",);

    Ok(())
}

/// Render redacted bytes as `🙈`.
fn bytes_to_redacted_string(bytes: &[u8]) -> FnResult<String> {
    Ok(String::from_utf8(bytes.to_vec())
        .map_err(|err| anyhow!("Failed to parse bytes to redacted string: {err}"))?
        .replace('\0', "🙈"))
}

// !!! Experiment with plugin controlled `verify` host function
// #[host_fn]
// extern "ExtismHost" {
//     fn verify(verifier_config: PluginVerifierConfig) -> Json<VerifierOutput>;
// }
// #[plugin_fn]
// pub unsafe fn plugin() -> FnResult<()> {
//     debug!("Plugin called...");

//     let verifier_config = PluginVerifierConfig { 
//         max_sent_data: None, max_sent_records: None, max_recv_data: None, max_recv_records: None
//     };
//     let output = unsafe { verify(verifier_config)? };

//     debug!("Verifier output: {:?}", output);
//     Ok(())
// }

// !!! Works
// #[plugin_fn]
// pub fn http_call() -> FnResult<()> {
//     let req = HttpRequest::new("https://swapi.debug/api/people/1");
//     debug!("Request to: {}", req.url);
//     let res= request::<()>(&req, None).map_err(|e| {
//         error!("Failed to make HTTP request: {}", e);
//         e
//     })?;
//     debug!("Response status: {}", res.status_code());
//     let body: Value = res.json().map_err(|e| {
//         error!("Failed to parse JSON response: {}", e);
//         e
//     })?;
//     debug!("Response: {:?}", body);
//     Ok(())
// }

// !!! Works
// #[plugin_fn]
// pub fn read_file() -> FnResult<()> {
//     let path = config::get("path")
//         .expect("Failed to get path from configuration")
//         .expect("Path not found in configuration");
//     debug!("Reading file: {}", path);
//     let content = fs::read_to_string(&path).map_err(|e| {
//         error!("Failed to read file {}: {}", path, e);
//         e
//     })?;
//     debug!("File content: {}", content);
//     Ok(())
// }

// !!! Does't work in extism plugin
// #[plugin_fn]
// pub fn http_call_with_hyper() -> FnResult<()> {
//     let rt = tokio::runtime::Runtime::new().unwrap();
//     rt.block_on(async {
//         let stream = tokio::net::TcpStream::connect("https://swapi.info").await.unwrap();
//         let io = TokioIo::new(stream);
//         let req = hyper::Request::builder()
//             .uri("https://swapi.info/api/people/1")
//             .body(Empty::<Bytes>::new())
//             .unwrap();

//         let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
//         let res = sender.send_request(req).await.unwrap();

//         println!("Response: {}", res.status());
//         println!("Headers: {:#?}\n", res.headers());
//     });
//     Ok(())
// }
