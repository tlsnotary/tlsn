/// This is a simple implementation of the notary server with minimal functionalities (without TLS, does not support WebSocket and configuration etc.)
/// For a more functional notary server implementation, please use the notary server in `../../notary-server`
use p256::pkcs8::DecodePrivateKey;
use std::env;

use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncReadCompatExt;

use tlsn_verifier::tls::{Verifier, VerifierConfig};

const NOTARY_SIGNING_KEY_PATH: &str = "../../../notary-server/fixture/notary/notary.key";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Allow passing an address to listen on as the first argument of this
    // program, but otherwise we'll just set up our TCP listener on
    // 127.0.0.1:8080 for connections.
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());

    // Next up we create a TCP listener which will listen for incoming
    // connections. This TCP listener is bound to the address we determined
    // above and must be associated with an event loop.
    let listener = TcpListener::bind(&addr).await.unwrap();

    println!("Listening on: {}", addr);

    // Load the notary signing key
    let signing_key =
        p256::ecdsa::SigningKey::read_pkcs8_pem_file(NOTARY_SIGNING_KEY_PATH).unwrap();

    loop {
        // Asynchronously wait for an inbound socket.
        let (socket, socket_addr) = listener.accept().await.unwrap();

        println!("Accepted connection from: {}", socket_addr);

        {
            let signing_key = signing_key.clone();

            // Spawn notarization task to be run concurrently
            tokio::spawn(async move {
                // Setup default config. Normally a different ID would be generated
                // for each notarization.
                let config = VerifierConfig::builder().id("example").build().unwrap();

                Verifier::new(config)
                    .notarize::<_, p256::ecdsa::Signature>(socket.compat(), &signing_key)
                    .await
                    .unwrap();
            });
        }
    }
}
