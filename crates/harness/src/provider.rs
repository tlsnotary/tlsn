#[cfg(not(target_arch = "wasm32"))]
mod native {
    use crate::{config::SERVER_LATENCY, io::Io};
    use anyhow::Result;
    use futures_limit::AsyncReadDelayExt;
    use tokio::net::TcpListener;
    use tokio_util::compat::TokioAsyncReadCompatExt;

    /// Provides IO for the prover.
    pub struct ProverProvider {
        server_addr: (String, u16),
        verifier_addr: (String, u16),
    }

    impl ProverProvider {
        /// Creates a new provider.
        pub(crate) fn new(server_addr: (String, u16), verifier_addr: (String, u16)) -> Self {
            Self {
                server_addr,
                verifier_addr,
            }
        }

        /// Provides a connection to the server.
        pub async fn provide_server(&self) -> Result<impl Io> {
            let io = tokio::net::TcpStream::connect(self.server_addr.clone()).await?;

            let (io, delay) = io.compat().delay(SERVER_LATENCY / 2);
            tokio::spawn(delay);

            Ok(io)
        }

        /// Provides a connection to the verifier.
        pub async fn provide_verifier(&self) -> Result<impl Io> {
            let io = tokio::net::TcpStream::connect(self.verifier_addr.clone()).await?;
            Ok(io.compat())
        }
    }

    /// Provides IO for the verifier.
    pub struct VerifierProvider {
        addr: (String, u16),
        listener: TcpListener,
    }

    impl VerifierProvider {
        pub(crate) async fn new(host: &str) -> Result<Self> {
            let listener = TcpListener::bind((host, 0)).await?;
            let port = listener.local_addr()?.port();

            Ok(Self {
                addr: (host.to_string(), port),
                listener,
            })
        }

        pub(crate) fn addr(&self) -> (String, u16) {
            self.addr.clone()
        }

        /// Provides a connection to the prover.
        pub async fn provide_prover(&self) -> Result<impl Io> {
            let (io, _) = self.listener.accept().await?;
            Ok(io.compat())
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use native::{ProverProvider, VerifierProvider};

#[cfg(target_arch = "wasm32")]
mod wasm {
    use crate::{config::SERVER_LATENCY, io::Io};
    use anyhow::Result;
    use futures::future::FutureExt;
    use futures_limit::AsyncReadDelayExt;

    pub enum VerifierAddr {
        Tcp { addr: (String, u16) },
        Ws { id: String },
    }

    pub struct ProverProvider {
        proxy_addr: (String, u16),
        server_addr: (String, u16),
        verifier_addr: VerifierAddr,
    }

    impl ProverProvider {
        /// Creates a new provider.
        pub(crate) fn new(
            proxy_addr: (String, u16),
            server_addr: (String, u16),
            verifier_addr: VerifierAddr,
        ) -> Self {
            Self {
                proxy_addr,
                server_addr,
                verifier_addr,
            }
        }

        /// Provides a connection to the server.
        pub async fn provide_server(&self) -> Result<impl Io> {
            let server_url = format!(
                "ws://{}:{}/tcp?addr={}%3A{}",
                &self.proxy_addr.0, self.proxy_addr.1, &self.server_addr.0, self.server_addr.1,
            );
            let (_, io) = ws_stream_wasm::WsMeta::connect(server_url, None).await?;

            let (io, delay) = io.into_io().delay(SERVER_LATENCY / 2);

            wasm_bindgen_futures::spawn_local(delay.map(|_| ()));

            Ok(io)
        }

        /// Provides a connection to the verifier.
        pub async fn provide_verifier(&self) -> Result<impl Io> {
            let url = match &self.verifier_addr {
                VerifierAddr::Tcp { addr } => {
                    format!(
                        "ws://{}:{}/tcp?addr={}%3A{}",
                        &self.proxy_addr.0, self.proxy_addr.1, &addr.0, addr.1,
                    )
                }
                VerifierAddr::Ws { id } => {
                    format!(
                        "ws://{}:{}/ws?id={}",
                        &self.proxy_addr.0, self.proxy_addr.1, &id,
                    )
                }
            };

            let (_, io) = ws_stream_wasm::WsMeta::connect(url, None).await?;

            Ok(io.into_io())
        }
    }

    pub struct VerifierProvider {
        proxy_addr: (String, u16),
        addr: String,
    }

    impl VerifierProvider {
        pub(crate) fn new(proxy_addr: (String, u16), addr: &str) -> Self {
            Self {
                proxy_addr,
                addr: addr.to_string(),
            }
        }

        /// Provides a connection to the prover.
        pub async fn provide_prover(&self) -> Result<impl Io> {
            let prover_url = format!(
                "ws://{}:{}/ws?id={}",
                &self.proxy_addr.0, self.proxy_addr.1, &self.addr,
            );

            let (_, io) = ws_stream_wasm::WsMeta::connect(prover_url, None).await?;

            Ok(io.into_io())
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use wasm::{ProverProvider, VerifierAddr, VerifierProvider};
