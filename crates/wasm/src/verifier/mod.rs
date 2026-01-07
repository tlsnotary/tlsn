mod config;

pub use config::VerifierConfig;

use async_io_stream::IoStream;
use enum_try_as_inner::EnumTryAsInner;
use tlsn::{
    config::tls_commit::TlsCommitProtocolConfig,
    connection::{ConnectionInfo, ServerName, TranscriptLength},
    transcript::ContentType,
    verifier::{state, Verifier},
    webpki::RootCertStore,
};
use tracing::info;
use wasm_bindgen::prelude::*;
use ws_stream_wasm::{WsMeta, WsStreamIo};

use crate::types::VerifierOutput;

type Result<T> = std::result::Result<T, JsError>;

#[wasm_bindgen(js_name = Verifier)]
pub struct JsVerifier {
    config: VerifierConfig,
    state: State,
}

#[derive(EnumTryAsInner)]
#[derive_err(Debug)]
#[allow(unused_assignments)]
enum State {
    Initialized(Verifier<state::Initialized>),
    Connected {
        verifier: Verifier<state::Initialized>,
        prover_conn: IoStream<WsStreamIo, Vec<u8>>,
    },
    Complete,
    Error,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "State")
    }
}

impl State {
    fn take(&mut self) -> Self {
        std::mem::replace(self, State::Error)
    }
}

#[wasm_bindgen(js_class = Verifier)]
impl JsVerifier {
    #[wasm_bindgen(constructor)]
    pub fn new(config: VerifierConfig) -> JsVerifier {
        let tlsn_config = tlsn::config::verifier::VerifierConfig::builder()
            .root_store(RootCertStore::mozilla())
            .build()
            .unwrap();
        JsVerifier {
            state: State::Initialized(Verifier::new(tlsn_config)),
            config,
        }
    }

    /// Connect to the prover.
    pub async fn connect(&mut self, prover_url: &str) -> Result<()> {
        let verifier = self.state.take().try_into_initialized()?;

        info!("Connecting to prover");

        let (_, prover_conn) = WsMeta::connect(prover_url, None).await?;
        let prover_conn = prover_conn.into_io();

        info!("Connected to prover");

        self.state = State::Connected {
            verifier,
            prover_conn,
        };

        Ok(())
    }

    /// Verifies the connection and finalizes the protocol.
    pub async fn verify(&mut self) -> Result<VerifierOutput> {
        let (verifier, mut prover_conn) = self.state.take().try_into_connected()?;

        let verifier = verifier.commit(&mut prover_conn).await?;
        let request = verifier.request();

        let TlsCommitProtocolConfig::Mpc(mpc_tls_config) = request.protocol() else {
            unimplemented!("only MPC protocol is supported");
        };

        let reject = if mpc_tls_config.max_sent_data() > self.config.max_sent_data {
            Some("max_sent_data is too large")
        } else if mpc_tls_config.max_recv_data() > self.config.max_recv_data {
            Some("max_recv_data is too large")
        } else if mpc_tls_config.max_sent_records() > self.config.max_sent_records {
            Some("max_sent_records is too large")
        } else if mpc_tls_config.max_recv_records_online() > self.config.max_recv_records_online {
            Some("max_recv_records_online is too large")
        } else {
            None
        };

        if reject.is_some() {
            verifier.reject(&mut prover_conn, reject).await?;
            return Err(JsError::new("protocol configuration rejected"));
        }

        let verifier = verifier
            .accept(&mut prover_conn)
            .await?
            .run(&mut prover_conn)
            .await?;

        let sent = verifier
            .tls_transcript()
            .sent()
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData)
            .map(|record| record.ciphertext.len())
            .sum::<usize>();

        let received = verifier
            .tls_transcript()
            .recv()
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData)
            .map(|record| record.ciphertext.len())
            .sum::<usize>();

        let connection_info = ConnectionInfo {
            time: verifier.tls_transcript().time(),
            version: *verifier.tls_transcript().version(),
            transcript_length: TranscriptLength {
                sent: sent as u32,
                received: received as u32,
            },
        };

        let (output, verifier) = verifier
            .verify(&mut prover_conn)
            .await?
            .accept(&mut prover_conn)
            .await?;
        verifier.close(&mut prover_conn).await?;

        self.state = State::Complete;

        Ok(VerifierOutput {
            server_name: output.server_name.map(|name| {
                let ServerName::Dns(name) = name;
                name.to_string()
            }),
            connection_info: connection_info.into(),
            transcript: output.transcript.map(|t| t.into()),
        })
    }
}
