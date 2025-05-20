// This example demonstrates how to use the Prover to acquire an attestation for
// an HTTP request sent to example.com. The attestation and secrets are saved to
// disk.

use std::{env, net::SocketAddr};

use clap::Parser;
use http_body_util::Empty;
use hyper::{
    body::{Body, Bytes},
    header::{
        HeaderValue, ACCEPT, ACCEPT_LANGUAGE, AUTHORIZATION, CONNECTION, CONTENT_TYPE, HOST,
        USER_AGENT as USER_AGENT_HEADER,
    },
    HeaderMap, Request, StatusCode,
};
use hyper_util::rt::TokioIo;
use spansy::Spanned;
use tokio::net::lookup_host;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;

use notary_client::{Accepted, NotarizationRequest, NotaryClient};
use tls_core::verify::WebPkiVerifier;
use tlsn_common::config::ProtocolConfig;
use tlsn_core::{request::RequestConfig, transcript::TranscriptCommitConfig, CryptoProvider};
use tlsn_examples::ExampleType;
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};
use tlsn_prover::{Prover, ProverConfig};
use tlsn_server_fixture::DEFAULT_FIXTURE_PORT;

// Setting of the application server.
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";
const SERVER_DOMAIN: &str = "youtube.com";

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// What data to notarize.
    #[clap(default_value_t, value_enum)]
    example_type: ExampleType,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    notarize(&args.example_type).await
}

async fn notarize(example_type: &ExampleType) -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let notary_host: String = env::var("NOTARY_HOST").unwrap_or("127.0.0.1".into());
    let notary_port: u16 = env::var("NOTARY_PORT")
        .map(|port| port.parse().expect("port should be valid integer"))
        .unwrap_or(7047);

    // Build a client to connect to the notary server.
    let notary_client = NotaryClient::builder()
        .host(notary_host)
        .port(notary_port)
        // WARNING: Always use TLS to connect to notary server, except if notary is running locally
        // e.g. this example, hence `enable_tls` is set to False (else it always defaults to True).
        .enable_tls(false)
        .build()
        .unwrap();

    // Send requests for configuration and notarization to the notary server.
    let notarization_request = NotarizationRequest::builder()
        // We must configure the amount of data we expect to exchange beforehand, which will
        // be preprocessed prior to the connection. Reducing these limits will improve
        // performance.
        .max_sent_data(1 << 15)
        .max_recv_data(tlsn_examples::MAX_RECV_DATA)
        .build()?;

    let Accepted {
        io: notary_connection,
        id: _session_id,
        ..
    } = notary_client
        .request_notarization(notarization_request)
        .await
        .expect("Could not connect to notary. Make sure it is running.");

    // Create a crypto provider accepting the server-fixture's self-signed
    // root certificate.
    //
    // This is only required for offline testing with the server-fixture. In
    // production, use `CryptoProvider::default()` instead.
    let crypto_provider = CryptoProvider::default();
    // Set up protocol configuration for prover.
    // Prover configuration.
    let prover_config = ProverConfig::builder()
        .server_name(SERVER_DOMAIN)
        .protocol_config(
            ProtocolConfig::builder()
                // We must configure the amount of data we expect to exchange beforehand, which will
                // be preprocessed prior to the connection. Reducing these limits will improve
                // performance.
                .max_sent_data(1 << 15)
                .max_recv_data(tlsn_examples::MAX_RECV_DATA)
                .build()?,
        )
        .crypto_provider(crypto_provider)
        .build()?;

    // Create a new prover and perform necessary setup.
    let prover = Prover::new(prover_config)
        .setup(notary_connection.compat())
        .await?;

    // Open a TCP connection to the server.
    let client_socket = tokio::net::TcpStream::connect(lookup().await).await?;

    // Bind the prover to the server connection.
    // The returned `mpc_tls_connection` is an MPC TLS connection to the server: all
    // data written to/read from it will be encrypted/decrypted using MPC with
    // the notary.
    let (mpc_tls_connection, prover_fut) = prover.connect(client_socket.compat()).await?;
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());

    // Spawn the prover task to be run concurrently in the background.
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the connection.
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection).await?;

    // Spawn the HTTP task to be run concurrently in the background.
    tokio::spawn(connection);

    // let request = Request::builder()
    //     .method("GET")
    //     .uri(format!("https://{}", SERVER_DOMAIN))
    //     .header(HOST, HeaderValue::from_static(SERVER_DOMAIN))
    //     .header(ACCEPT, HeaderValue::from_static("*/*"))
    //     .header(USER_AGENT_HEADER, USER_AGENT)
    //     .header("Accept-Encoding", HeaderValue::from_static("identity"))
    //     .header(CONNECTION, "close")
    //     .body(Empty::<Bytes>::new())
    //     .unwrap();
    let request = build_request();
    println!("Request is {:?}", request);

    println!("Starting an MPC TLS connection with the server");

    // Send the request to the server and wait for the response.
    let response = request_sender.send_request(request).await?;

    println!("Got a response from the server: {}", response.status());

    assert!(response.status() == StatusCode::OK);

    // The prover task should be done now, so we can await it.
    let prover = prover_task.await??;

    // Prepare for notarization.
    let mut prover = prover.start_notarize();

    // Parse the HTTP transcript.
    let transcript = HttpTranscript::parse(prover.transcript())?;

    let body_content = &transcript.responses[0].body.as_ref().unwrap().content;
    let body = String::from_utf8_lossy(body_content.span().as_bytes());

    match body_content {
        tlsn_formats::http::BodyContent::Json(_json) => {
            let parsed = serde_json::from_str::<serde_json::Value>(&body)?;
            debug!("{}", serde_json::to_string_pretty(&parsed)?);
        }
        tlsn_formats::http::BodyContent::Unknown(_span) => {
            debug!("{}", &body);
        }
        _ => {}
    }

    // Commit to the transcript.
    let mut builder = TranscriptCommitConfig::builder(prover.transcript());

    // This commits to various parts of the transcript separately (e.g. request
    // headers, response headers, response body and more). See https://docs.tlsnotary.org//protocol/commit_strategy.html
    // for other strategies that can be used to generate commitments.
    DefaultHttpCommitter::default().commit_transcript(&mut builder, &transcript)?;

    prover.transcript_commit(builder.build()?);

    // Build an attestation request.
    let builder = RequestConfig::builder();

    // Optionally, add an extension to the attestation if the notary supports it.
    // builder.extension(Extension {
    //     id: b"example.name".to_vec(),
    //     value: b"Bobert".to_vec(),
    // });

    let request_config = builder.build()?;

    let (attestation, secrets) = prover.finalize(&request_config).await?;

    println!("Notarization complete!");

    // Write the attestation to disk.
    let attestation_path = tlsn_examples::get_file_path(example_type, "attestation");
    let secrets_path = tlsn_examples::get_file_path(example_type, "secrets");

    tokio::fs::write(&attestation_path, bincode::serialize(&attestation)?).await?;

    // Write the secrets to disk.
    tokio::fs::write(&secrets_path, bincode::serialize(&secrets)?).await?;

    println!("Notarization completed successfully!");
    println!(
        "The attestation has been written to `{attestation_path}` and the \
        corresponding secrets to `{secrets_path}`."
    );

    Ok(())
}

fn build_request() -> Request<String> {
    let mut headers = HeaderMap::new();
    headers.insert("Accept-Encoding", HeaderValue::from_static("identity"));
    headers.insert(HOST, HeaderValue::from_static("youtube.com"));
    headers.insert(ACCEPT, HeaderValue::from_static("*/*"));
    headers.insert(CONNECTION, HeaderValue::from_static("close"));
    headers.insert(
        ACCEPT_LANGUAGE,
        HeaderValue::from_static("en-GB,en-US;q=0.9,en;q=0.8"),
    );
    headers.insert(AUTHORIZATION, HeaderValue::from_static(
        "SAPISIDHASH 1744286082_09d2d0be97bc35e0a44d2bd824209e6b5570f845_u SAPISID1PHASH 1744286082_09d2d0be97bc35e0a44d2bd824209e6b5570f845_u SAPISID3PHASH 1744286082_09d2d0be97bc35e0a44d2bd824209e6b5570f845_u"
    ));
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert("priority", HeaderValue::from_static("u=1, i"));
    headers.insert(
        "sec-ch-ua",
        HeaderValue::from_static(
            r#""Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135""#,
        ),
    );
    headers.insert("sec-ch-ua-arch", HeaderValue::from_static("\"arm\""));
    headers.insert("sec-ch-ua-bitness", HeaderValue::from_static("\"64\""));
    headers.insert(
        "sec-ch-ua-form-factors",
        HeaderValue::from_static("\"Desktop\""),
    );
    headers.insert(
        "sec-ch-ua-full-version",
        HeaderValue::from_static("\"135.0.7049.42\""),
    );
    headers.insert("sec-ch-ua-full-version-list", HeaderValue::from_static(r#""Google Chrome";v="135.0.7049.42", "Not-A.Brand";v="8.0.0.0", "Chromium";v="135.0.7049.42""#));
    headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
    headers.insert("sec-ch-ua-model", HeaderValue::from_static("\"\""));
    headers.insert("sec-ch-ua-platform", HeaderValue::from_static("\"macOS\""));
    headers.insert(
        "sec-ch-ua-platform-version",
        HeaderValue::from_static("\"14.4.0\""),
    );
    headers.insert("sec-ch-ua-wow64", HeaderValue::from_static("?0"));
    headers.insert("sec-fetch-dest", HeaderValue::from_static("empty"));
    headers.insert("sec-fetch-mode", HeaderValue::from_static("same-origin"));
    headers.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
    headers.insert(
        "x-client-data",
        HeaderValue::from_static(
            "CIe2yQEIorbJAQipncoBCLvcygEIkqHLAQiRo8sBCIagzQEI3dbOAQi25c4BCLnmzgEIvOfOARin5s4B",
        ),
    );
    headers.insert("x-goog-authuser", HeaderValue::from_static("0"));
    headers.insert(
        "x-goog-visitor-id",
        HeaderValue::from_static(
            "Cgt4bzFrMUE5SzBCcyiY3t6_BjInCgJQTBIhEh0SGwsMDg8QERITFBUWFxgZGhscHR4fICEiIyQlJiAz",
        ),
    );
    headers.insert(
        "x-origin",
        HeaderValue::from_static("https://www.youtube.com"),
    );
    headers.insert(
        "x-youtube-bootstrap-logged-in",
        HeaderValue::from_static("true"),
    );
    headers.insert("x-youtube-client-name", HeaderValue::from_static("1"));
    headers.insert(
        "x-youtube-client-version",
        HeaderValue::from_static("2.20250409.00.00"),
    );
    let mut request_builder = Request::builder()
        .method("POST")
        .uri("https://www.youtube.com/youtubei/v1/subscription/subscribe?prettyPrint=false");
    // Using "identity" instructs the Server not to use compression for its HTTP response.
    // TLSNotary tooling does not support compression.

    *request_builder.headers_mut().unwrap() = headers;

    let body = r#"
{
  "context": {
    "client": {
      "hl": "en",
      "gl": "PL",
      "remoteHost": "195.136.151.237",
      "deviceMake": "Apple",
      "deviceModel": "",
      "visitorData": "Cgt4bzFrMUE5SzBCcyiY3t6_BjInCgJQTBIhEh0SGwsMDg8QERITFBUWFxgZGhscHR4fICEiIyQlJiAz",
      "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36,gzip(gfe)",
      "clientName": "WEB",
      "clientVersion": "2.20250409.00.00",
      "osName": "Macintosh",
      "osVersion": "10_15_7",
      "originalUrl": "https://www.youtube.com/@vlayerxyz",
      "screenPixelDensity": 2,
      "platform": "DESKTOP",
      "clientFormFactor": "UNKNOWN_FORM_FACTOR",
      "configInfo": {
        "appInstallData": "CJje3r8GEJ35zhwQvZmwBRDN0bEFEPirsQUQvbauBRCD7s4cEMn3rwUQ26-vBRC52c4cEODNsQUQo-_...",
        "coldConfigData": "CJje3r8GEPG6rQUQxIWuBRC9tq4FEOLUrgUQvYqwBRCe0LAFEM_SsAUQ4_iwBRCkvrEFENK_sQUQ18G...",
        "coldHashData": "CJje3r8GEhMzODk1ODM2OTIwNzIzMTUzNzYwGJje3r8GMjJBT2pGb3gyNDBtVDBHQklDbkNnX28wcE5...",
        "hotHashData": "CJje3r8GEhM4MzY3MjA3NjYxMzA1MzUyNzg1GJje3r8GKJTk_BIopdD9Eiiekf4SKMjK_hIot-r-Eij..."
      },
      "screenDensityFloat": 2,
      "userInterfaceTheme": "USER_INTERFACE_THEME_LIGHT",
      "timeZone": "Europe/Warsaw",
      "browserName": "Chrome",
      "browserVersion": "135.0.0.0",
      "acceptHeader": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
      "deviceExperimentId": "ChxOelE1TVRZME9UQXlOREF4TVRVNE9Ua3lOUT09EJje3r8GGJje3r8G",
      "rolloutToken": "CJjB6ajg5a-cZhCvs6T95vWKAxji_Pr0kcuMAw==",
      "screenWidthPoints": 1349,
      "screenHeightPoints": 524,
      "utcOffsetMinutes": 120,
      "connectionType": "CONN_CELLULAR_4G",
      "memoryTotalKbytes": "8000000",
      "mainAppWebInfo": {
        "graftUrl": "https://www.youtube.com/@vlayerxyz",
        "pwaInstallabilityStatus": "PWA_INSTALLABILITY_STATUS_CAN_BE_INSTALLED",
        "webDisplayMode": "WEB_DISPLAY_MODE_BROWSER",
        "isWebNativeShareAvailable": true
      }
    },
    "user": {
      "lockedSafetyMode": false
    },
    "request": {
      "useSsl": true,
      "internalExperimentFlags": [],
      "consistencyTokenJars": [
        {
          "encryptedTokenJarContents": "AKreu9ue4BdEK43XUApuBMcxffPRC_N4DgEbNoJOF1QinpT0pgPTKSAjSEKSA1Sl9H0Bl0zpO7Q_bTo_6e1d743UK6OgjDYAQgJUThBZnK3KJwj1ZwwzKfyBRw",
          "expirationSeconds": "600"
        }
      ]
    },
    "clientScreenNonce": "VXDEcL0-zoS2TxS5",
    "clickTracking": {
      "clickTrackingParams": "CCQQmysYASITCIfohNyxzYwDFapzegUdVIgRsjIJY2hhbm5lbHM0"
    },
    "adSignalsInfo": {
      "params": [
        {"key": "dt", "value": "1744285464875"},
        {"key": "flash", "value": "0"},
        {"key": "frm", "value": "0"},
        {"key": "u_tz", "value": "120"},
        {"key": "u_his", "value": "1"},
        {"key": "u_h", "value": "1117"},
        {"key": "u_w", "value": "1728"},
        {"key": "u_ah", "value": "1010"},
        {"key": "u_aw", "value": "1728"},
        {"key": "u_cd", "value": "30"},
        {"key": "bc", "value": "31"},
        {"key": "bih", "value": "524"},
        {"key": "biw", "value": "1334"},
        {"key": "brdim", "value": "0,38,0,38,1728,38,1728,1009,1349,524"},
        {"key": "vis", "value": "1"},
        {"key": "wgl", "value": "true"},
        {"key": "ca_type", "value": "image"}
      ],
      "bid": "ANyPxKoqWUeyzHCtjzeyJvKJ1gFjRq1MEMoOBl3rSI9PbRHprV-D2A45DTSmc6DB_InmaVjo5-G0-aonf7XBvMUCEVrbHAUwow"
    }
  },
  "channelIds": ["UCm933GmbDBEV7tiOuYkMeWQ"],
  "params": "EgIIAhgA"
}
"#;

    let request = request_builder.body(body.to_string()).unwrap();
    request
}

async fn lookup() -> SocketAddr {
    let mut host = lookup_host(format!("{}:{}", SERVER_DOMAIN, "443"))
        .await
        .unwrap();
    let host = host.next().unwrap();
    println!("host is {:?}", host);
    host
}
