use extism_pdk::{host_fn, debug, plugin_fn, FnResult, FromBytes, Json, ToBytes};
use serde::{Deserialize, Serialize};
use tlsn_core::VerifierOutput;

#[derive(Serialize, Deserialize, FromBytes, ToBytes, Debug)]
#[encoding(Json)]
struct PluginVerifierConfig {
    /// Maximum number of bytes that can be sent.
    max_sent_data: Option<usize>,
     /// Maximum number of application data records that can be sent.
    max_sent_records: Option<usize>,
    /// Maximum number of bytes that can be received.
    max_recv_data: Option<usize>,
    /// Maximum number of application data records that can be received.
    max_recv_records: Option<usize>,
}

#[host_fn]
extern "ExtismHost" {
    fn verify(verifier_config: PluginVerifierConfig) -> Json<VerifierOutput>;
}

#[plugin_fn]
pub unsafe fn plugin() -> FnResult<()> {
    debug!("Plugin called...");

    let verifier_config = PluginVerifierConfig { 
        max_sent_data: None, max_sent_records: None, max_recv_data: None, max_recv_records: None
    };
    let output = unsafe { verify(verifier_config)? };

    debug!("Verifier output: {:?}", output);
    Ok(())
}

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
