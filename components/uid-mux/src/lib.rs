//! This library provides tools to multiplex a connection and uses [yamux] under the hood.
//!
//! To use this library, instantiate a [UidYamux] by providing an underlying socket (anything which
//! implements [AsyncRead] and [AsyncWrite]). After running [run](UidYamux::run) in the background
//! you can create controls with [control](UidYamux::control), which can be easily passed around.
//! They allow to open new streams ([get_stream](UidYamuxControl::get_stream)) by providing unique
//! stream ids.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;

use futures::{
    channel::oneshot, stream::FuturesUnordered, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
    StreamExt,
};
use utils_aio::mux::{MuxStream, MuxerError};

pub use yamux;

#[derive(Debug, Default)]
struct MuxState {
    stream_ids: HashSet<String>,
    waiting_callers: HashMap<String, oneshot::Sender<Result<yamux::Stream, MuxerError>>>,
    waiting_streams: HashMap<String, yamux::Stream>,
}

/// A wrapper around [yamux] to facilitate multiplexing with unique stream ids.
pub struct UidYamux<T> {
    mode: yamux::Mode,
    conn: Option<yamux::ControlledConnection<T>>,
    control: yamux::Control,
    state: Arc<Mutex<MuxState>>,
}

impl<T> std::fmt::Debug for UidYamux<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UidYamux")
            .field("mode", &self.mode)
            .field("conn", &"{{ ... }}")
            .field("control", &self.control)
            .field("state", &self.state)
            .finish()
    }
}

/// A muxer control for [opening streams](Self::get_stream) with the remote
#[derive(Debug, Clone)]
pub struct UidYamuxControl {
    mode: yamux::Mode,
    control: yamux::Control,
    state: Arc<Mutex<MuxState>>,
}

impl UidYamuxControl {
    /// shutdown the connection properly
    pub async fn shutdown(&mut self) -> Result<(), MuxerError>{
        self.control.close().await.map_err(|err| MuxerError::InternalError(format!("shutdown error: {0:?}", err)))
   }
}

impl<T> UidYamux<T>
where
    T: AsyncWrite + AsyncRead + Send + Unpin + 'static,
{
    /// Creates a new muxer with the provided config and socket
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "info", skip(socket), ret)
    )]
    pub fn new(config: yamux::Config, socket: T, mode: yamux::Mode) -> Self {
        let (control, conn) = yamux::Control::new(yamux::Connection::new(socket, config, mode));

        Self {
            mode,
            conn: Some(conn),
            control,
            state: Arc::new(Mutex::new(MuxState::default())),
        }
    }

    /// Runs the muxer.
    ///
    /// This method will poll the underlying connection for new streams and
    /// handle them appropriately.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip(self), err)
    )]
    pub async fn run(&mut self) -> Result<(), MuxerError> {
        let mut conn = Box::pin(
            self.conn
                .take()
                .ok_or_else(|| MuxerError::InternalError("connection shutdown".to_string()))?
                .fuse(),
        );

        // The size of this buffer is bounded by yamux max stream config.
        let mut pending_streams = FuturesUnordered::new();
        loop {
            futures::select! {
                // Handle incoming streams
                stream = conn.select_next_some() => {
                    if self.mode == yamux::Mode::Client {
                        return Err(MuxerError::InternalError(
                            "client mode cannot accept incoming streams".to_string(),
                        ));
                    }

                    let mut stream =
                        stream.map_err(|e| MuxerError::InternalError(format!("connection error: {0:?}", e)))?;

                    pending_streams.push(async move {
                        let stream_id = read_stream_id(&mut stream).await?;

                        Ok::<_, MuxerError>((stream_id, stream))
                    });
                }
                // Handle streams for which we've received the id
                stream = pending_streams.select_next_some() => {
                    let (stream_id, stream) = stream?;

                    let mut state = self.state.lock().unwrap();
                    state.stream_ids.insert(stream_id.clone());
                    if let Some(sender) = state.waiting_callers.remove(&stream_id) {
                        // ignore if receiver dropped
                        _ = sender.send(Ok(stream));
                    } else {
                        state.waiting_streams.insert(stream_id, stream);
                    }
                }
                complete => return Ok(()),
            }
        }
    }

    /// Returns a [UidYamuxControl] that can be used to open streams.
    pub fn control(&self) -> UidYamuxControl {
        UidYamuxControl {
            mode: self.mode,
            control: self.control.clone(),
            state: self.state.clone(),
        }
    }
}

#[cfg_attr(
    feature = "tracing",
    tracing::instrument(level = "debug", skip(stream), err)
)]
async fn write_stream_id<T: AsyncWrite + Unpin>(
    stream: &mut T,
    id: &str,
) -> Result<(), std::io::Error> {
    let id = id.as_bytes();

    if id.len() > u32::MAX as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "id too long",
        ));
    }

    stream.write_all(&(id.len() as u32).to_be_bytes()).await?;
    stream.write_all(id).await?;

    Ok(())
}

#[cfg_attr(
    feature = "tracing",
    tracing::instrument(level = "debug", skip(stream), ret, err)
)]
async fn read_stream_id<T: AsyncRead + Unpin>(stream: &mut T) -> Result<String, std::io::Error> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await?;

    let len = u32::from_be_bytes(len) as usize;

    let mut id = vec![0u8; len];
    stream.read_exact(&mut id).await?;

    Ok(String::from_utf8_lossy(&id).to_string())
}

#[async_trait]
impl MuxStream for UidYamuxControl {
    type Stream = yamux::Stream;

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "info", skip(self), err)
    )]
    async fn get_stream(&mut self, id: &str) -> Result<Self::Stream, MuxerError> {
        match self.mode {
            yamux::Mode::Client => {
                if !self.state.lock().unwrap().stream_ids.insert(id.to_string()) {
                    return Err(MuxerError::DuplicateStreamId(id.to_string()));
                }

                let mut stream = self.control.open_stream().await.map_err(|e| {
                    MuxerError::InternalError(format!("failed to open stream: {}", e))
                })?;

                write_stream_id(&mut stream, id).await?;

                Ok(stream)
            }
            yamux::Mode::Server => {
                let receiver = {
                    let mut state = self.state.lock().unwrap();

                    // If we already have the stream, return it
                    if let Some(stream) = state.waiting_streams.remove(id) {
                        return Ok(stream);
                    }

                    // Prevent duplicate stream ids
                    if state.stream_ids.contains(id) {
                        return Err(MuxerError::DuplicateStreamId(id.to_string()));
                    }

                    let (sender, receiver) = oneshot::channel();
                    state.waiting_callers.insert(id.to_string(), sender);

                    receiver
                };

                receiver
                    .await
                    .map_err(|_| MuxerError::InternalError("sender dropped".to_string()))?
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::{AsyncReadExt, AsyncWriteExt, FutureExt};
    use tokio_util::compat::TokioAsyncReadCompatExt;

    use super::*;

    async fn create_pair() -> (UidYamuxControl, UidYamuxControl) {
        let (socket_a, socket_b) = tokio::io::duplex(1024);

        let mut mux_a = UidYamux::new(
            yamux::Config::default(),
            socket_a.compat(),
            yamux::Mode::Client,
        );
        let mut mux_b = UidYamux::new(
            yamux::Config::default(),
            socket_b.compat(),
            yamux::Mode::Server,
        );

        let control_a = mux_a.control();
        let control_b = mux_b.control();

        tokio::spawn(async move {
            mux_a.run().await.unwrap();
        });

        tokio::spawn(async move {
            mux_b.run().await.unwrap();
        });

        (control_a, control_b)
    }

    #[tokio::test]
    async fn test_mux() {
        let (mut control_a, mut control_b) = create_pair().await;

        let (mut stream_a, mut stream_b) =
            tokio::try_join!(control_a.get_stream("test"), control_b.get_stream("test")).unwrap();

        let msg = b"hello world";

        stream_a.write_all(msg).await.unwrap();
        stream_a.flush().await.unwrap();

        let mut buf = [0u8; 11];
        stream_b.read_exact(&mut buf).await.unwrap();

        assert_eq!(&buf, msg);
    }

    #[tokio::test]
    async fn test_mux_multiple_streams() {
        let (mut control_a, mut control_b) = create_pair().await;

        let (mut stream_a, mut stream_b) =
            tokio::try_join!(control_a.get_stream("test"), control_b.get_stream("test")).unwrap();

        let (mut stream_c, mut stream_d) =
            tokio::try_join!(control_a.get_stream("test2"), control_b.get_stream("test2")).unwrap();

        let msg = b"hello world";

        stream_d.write_all(msg).await.unwrap();
        stream_d.flush().await.unwrap();

        let mut buf = [0u8; 11];
        stream_c.read_exact(&mut buf).await.unwrap();

        assert_eq!(&buf, msg);

        let msg = b"hello world2";

        stream_a.write_all(msg).await.unwrap();
        stream_a.flush().await.unwrap();

        let mut buf = [0u8; 12];
        stream_b.read_exact(&mut buf).await.unwrap();

        assert_eq!(&buf, msg);
    }

    #[tokio::test]
    async fn test_mux_no_duplicates() {
        let (mut control_a, mut control_b) = create_pair().await;

        let _ =
            tokio::try_join!(control_a.get_stream("test"), control_b.get_stream("test")).unwrap();

        let (err_a, err_b) =
            tokio::join!(control_a.get_stream("test"), control_b.get_stream("test"));

        assert!(err_a.is_err());
        assert!(err_b.is_err());
    }

    #[tokio::test]
    async fn test_mux_send_before_opened() {
        let (mut control_a, mut control_b) = create_pair().await;

        let mut stream_a = control_a.get_stream("test").await.unwrap();

        let msg = b"hello world";

        stream_a.write_all(msg).await.unwrap();
        stream_a.flush().await.unwrap();

        let mut stream_b = control_b.get_stream("test").await.unwrap();

        let mut buf = [0u8; 11];
        let read = futures::select! {
            read = stream_b.read(&mut buf).fuse() => read.unwrap(),
            _ = tokio::time::sleep(std::time::Duration::from_secs(5)).fuse() => panic!("timed out"),
        };

        assert_eq!(&buf[..read], msg);
    }
}
