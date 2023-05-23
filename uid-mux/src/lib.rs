use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;

use bytes::Bytes;
use futures::{
    channel::oneshot, stream::FuturesUnordered, AsyncRead, AsyncWrite, SinkExt, StreamExt,
};
use tokio_util::{codec::LengthDelimitedCodec, compat::FuturesAsyncReadCompatExt};
use utils_aio::mux::{MuxStream, MuxerError};

pub use yamux;

#[derive(Debug, Default)]
struct MuxState {
    stream_ids: HashSet<String>,
    waiting_callers: HashMap<String, oneshot::Sender<Result<yamux::Stream, MuxerError>>>,
    waiting_streams: HashMap<String, yamux::Stream>,
}

/// A wrapper around yamux to facilitate multiplexing with unique stream ids.
pub struct UidYamux<T> {
    mode: yamux::Mode,
    conn: Option<yamux::ControlledConnection<T>>,
    control: yamux::Control,
    state: Arc<Mutex<MuxState>>,
}

/// A muxer control for opening streams with the remote
#[derive(Debug, Clone)]
pub struct UidYamuxControl {
    mode: yamux::Mode,
    control: yamux::Control,
    state: Arc<Mutex<MuxState>>,
}

impl<T> UidYamux<T>
where
    T: AsyncWrite + AsyncRead + Send + Unpin + 'static,
{
    /// Creates a new muxer with the provided config and socket
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
    pub async fn run(&mut self) -> Result<(), MuxerError> {
        // Use a length-delimited codec for transporting stream ids to the remote
        let mut stream_id_codec = LengthDelimitedCodec::builder();
        stream_id_codec
            .max_frame_length(256)
            .length_field_type::<u8>();

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

                    let mut framed_stream = stream_id_codec
                        .new_read(
                            stream.map_err(|e| MuxerError::InternalError(format!("connection error: {0:?}", e)))?
                                .compat()
                        );

                    pending_streams.push(async move {
                        let stream_id = framed_stream.next().await.ok_or_else(|| {
                            MuxerError::InternalError("stream closed before id received".to_string())
                        })??;

                        let stream_id = String::from_utf8_lossy(&stream_id).to_string();

                        Ok::<_, MuxerError>((stream_id, framed_stream.into_inner().into_inner()))
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

    /// Returns a `UidYamuxControl` that can be used to open streams.
    pub fn control(&self) -> UidYamuxControl {
        UidYamuxControl {
            mode: self.mode,
            control: self.control.clone(),
            state: self.state.clone(),
        }
    }
}

#[async_trait]
impl MuxStream for UidYamuxControl {
    type Stream = yamux::Stream;

    async fn get_stream(&mut self, id: &str) -> Result<Self::Stream, MuxerError> {
        match self.mode {
            yamux::Mode::Client => {
                if !self.state.lock().unwrap().stream_ids.insert(id.to_string()) {
                    return Err(MuxerError::DuplicateStreamId(id.to_string()));
                }

                let stream = self.control.open_stream().await.map_err(|e| {
                    MuxerError::InternalError(format!("failed to open stream: {}", e))
                })?;

                let mut framed_stream = LengthDelimitedCodec::builder()
                    .max_frame_length(256)
                    .length_field_type::<u8>()
                    .new_write(stream.compat());

                framed_stream
                    .send(Bytes::from(id.to_string()))
                    .await
                    .map_err(|e| {
                        MuxerError::InternalError(format!("failed to write stream id: {}", e))
                    })?;

                Ok(framed_stream.into_inner().into_inner())
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
    use futures::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::compat::TokioAsyncReadCompatExt;

    use super::*;

    async fn create_pair() -> (UidYamuxControl, UidYamuxControl) {
        let (socket_a, socket_b) = tokio::io::duplex(1024);

        let mut mux_a = UidYamux::new(
            yamux::Config::default(),
            socket_a.compat(),
            yamux::Mode::Server,
        );
        let mut mux_b = UidYamux::new(
            yamux::Config::default(),
            socket_b.compat(),
            yamux::Mode::Client,
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
}
