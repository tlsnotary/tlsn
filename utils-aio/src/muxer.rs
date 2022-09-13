use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use futures::{
    channel::{mpsc, oneshot},
    AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, FutureExt, StreamExt,
};
use yamux;

#[derive(Debug, thiserror::Error)]
pub enum MuxerError {
    #[error("Connection closed unexpectedly")]
    UnexpectedConnectionClosed,
    #[error("Connection error occurred: {0}")]
    ConnectionError(String),
    #[error("IO error")]
    IOError(#[from] std::io::Error),
    #[error("Encountered error opening or accepting substream: {0:?}")]
    SubstreamError(String),
    #[error("Duplicate stream id: {0:?}")]
    DuplicateStreamId(String),
    #[error("Encountered internal error: {0:?}")]
    InternalError(String),
}

#[async_trait]
pub trait StreamMuxer {
    type Substream: AsyncWrite + AsyncRead + Send;

    /// Opens a new substream with the remote using the provided id
    async fn open_substream(&mut self, id: String) -> Result<Self::Substream, MuxerError>;

    /// Accepts a substream opened by the remote with the provided id
    async fn accept_substream(&mut self, id: String) -> Result<Self::Substream, MuxerError>;
}

pub enum MuxerCommand {
    OpenStream(String, oneshot::Sender<Result<yamux::Stream, MuxerError>>),
    AcceptStream(String, oneshot::Sender<Result<yamux::Stream, MuxerError>>),
}

const MAX_COMMAND_BACKLOG: usize = 32;

pub struct YamuxMuxer<T>
where
    T: AsyncWrite + AsyncRead + Send + Unpin,
{
    conn: yamux::Connection<T>,
    yamux_control: yamux::Control,
    stream_ids: HashSet<String>,
    control_receiver: mpsc::Receiver<MuxerCommand>,
    control_sender: mpsc::Sender<MuxerCommand>,
    pending: HashMap<String, oneshot::Sender<Result<yamux::Stream, MuxerError>>>,
    buffer_pending: HashMap<String, yamux::Stream>,
    buffer_remote: Vec<yamux::Stream>,
}

impl From<yamux::ConnectionError> for MuxerError {
    fn from(e: yamux::ConnectionError) -> Self {
        todo!()
    }
}

impl<T> YamuxMuxer<T>
where
    T: AsyncWrite + AsyncRead + Send + Unpin + 'static,
{
    /// Creates new muxer in client mode
    pub fn new_client(socket: T) -> Self {
        let (control_sender, control_receiver) = mpsc::channel(MAX_COMMAND_BACKLOG);
        let conn = yamux::Connection::new(socket, yamux::Config::default(), yamux::Mode::Client);
        let yamux_control = conn.control();
        Self {
            conn,
            yamux_control,
            stream_ids: HashSet::default(),
            control_sender,
            control_receiver,
            pending: HashMap::default(),
            buffer_pending: HashMap::default(),
            buffer_remote: Vec::default(),
        }
    }

    /// Creates new muxer in server mode
    pub fn new_server(socket: T) -> Self {
        let (control_sender, control_receiver) = mpsc::channel(MAX_COMMAND_BACKLOG);
        let conn = yamux::Connection::new(socket, yamux::Config::default(), yamux::Mode::Server);
        let yamux_control = conn.control();
        Self {
            conn,
            yamux_control,
            stream_ids: HashSet::default(),
            control_sender,
            control_receiver,
            pending: HashMap::default(),
            buffer_pending: HashMap::default(),
            buffer_remote: Vec::default(),
        }
    }

    /// Returns muxer control which can be used to open and accept new substreams
    pub fn control(&self) -> YamuxMuxerControl {
        YamuxMuxerControl {
            control_sender: self.control_sender.clone(),
        }
    }

    /// Processes pending substreams
    ///
    /// This function must be called repeatedly to make progress
    pub async fn next_stream(&mut self) -> Result<(), MuxerError> {
        let conn = &mut self.conn;
        let stream_fut = conn.next_stream().fuse();
        futures::pin_mut!(stream_fut);

        // continuously poll for new streams and push it into the buffer if received
        // while waiting for new substream, process any pending commands and buffers
        loop {
            // gather up all the matching streams from pending buffers
            let matches = self
                .pending
                .keys()
                .filter(|id| self.buffer_pending.contains_key(*id))
                .cloned()
                .collect::<Vec<String>>();

            // drain pending streams from buffers
            for id in matches {
                let sender = self.pending.remove(&id).expect("key should be present");
                let stream = self
                    .buffer_pending
                    .remove(&id)
                    .expect("key should be present");
                // send to receiver, ignore if receiver dropped
                _ = sender.send(Ok(stream));
            }

            // process new streams, sending them to the receiver immediately if possible
            // otherwise putting them into internal buffer
            for stream in self.buffer_remote.drain(..) {
                // Wait until we receive the corresponding stream id
                // Fail if the stream id is not received within 5 seconds
                let mut stream_id = String::new();
                let mut reader = futures::io::BufReader::new(stream);
                if let Err(_) = async_std::io::timeout(
                    std::time::Duration::from_secs(5),
                    reader.read_line(&mut stream_id),
                )
                .await
                {
                    // todo handle this properly
                    continue;
                }

                // Pop new line off stream id
                _ = stream_id.pop();

                let stream = reader.into_inner();
                if let Some(sender) = self.pending.remove(&stream_id) {
                    // send to receiver, ignore if receiver dropped
                    _ = sender.send(Ok(stream));
                } else {
                    // the size of this buffer is bounded by the configuration of yamux (max open streams)
                    self.buffer_pending.insert(stream_id, stream);
                }
            }

            futures::select! {
                stream = stream_fut => {
                    // if we receive a new stream push it into the buffer and return
                    if let Some(stream) = stream? {
                        self.buffer_remote.push(stream);
                    }
                    return Ok(())
                },
                cmd = self.control_receiver.next().fuse() => {
                    // if we receive a new command, process it
                    if let Some(cmd) = cmd {
                        match cmd {
                            MuxerCommand::OpenStream(id, sender) => {
                                if self.stream_ids.contains(&id) {
                                    // duplicate stream return error
                                    _ = sender.send(Err(MuxerError::DuplicateStreamId(id)));
                                } else {
                                    // open stream, and send new-line delimited stream id
                                    let mut stream = self.yamux_control.open_stream().await?;
                                    stream.write_all(format!("{}\n", &id).as_bytes()).await?;
                                    self.stream_ids.insert(id);
                                    _ = sender.send(Ok(stream));
                                }
                            },
                            MuxerCommand::AcceptStream(id, sender) => {
                                self.pending.insert(id, sender);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// This control can be used to open and accept new substreams
///
/// It can be cloned and used concurrently
#[derive(Clone)]
pub struct YamuxMuxerControl {
    control_sender: mpsc::Sender<MuxerCommand>,
}

#[async_trait]
impl StreamMuxer for YamuxMuxerControl {
    type Substream = yamux::Stream;

    async fn open_substream(&mut self, id: String) -> Result<Self::Substream, MuxerError> {
        let (sender, receiver) = oneshot::channel::<Result<yamux::Stream, MuxerError>>();
        self.control_sender
            .try_send(MuxerCommand::OpenStream(id, sender))
            .map_err(|_| MuxerError::InternalError("failed to send control command".to_string()))?;

        receiver
            .await
            .map_err(|_| MuxerError::InternalError("muxer dropped sender".to_string()))?
    }

    async fn accept_substream(&mut self, id: String) -> Result<Self::Substream, MuxerError> {
        let (sender, receiver) = oneshot::channel::<Result<yamux::Stream, MuxerError>>();
        self.control_sender
            .try_send(MuxerCommand::AcceptStream(id, sender))
            .map_err(|_| MuxerError::InternalError("failed to send control command".to_string()))?;

        receiver
            .await
            .map_err(|_| MuxerError::InternalError("muxer dropped sender".to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::duplex;
    use tokio_util::compat::TokioAsyncReadCompatExt;

    #[tokio::test]
    async fn test() {
        let (client, server) = duplex(1024);

        let client_task = async move {
            let mut client_muxer = YamuxMuxer::new_client(client.compat());
            let mut client_muxer_control = client_muxer.control();

            let poll_task = tokio::spawn(async move {
                loop {
                    client_muxer.next_stream().await.unwrap();
                }
            });

            let open_task = tokio::spawn(async move {
                let fut = client_muxer_control.open_substream("stream 0".to_string());
                println!("client: opening substream");
                let substream = fut.await.unwrap();
                println!("client: remote accepted substream");
            });

            _ = tokio::join!(poll_task, open_task);
        };

        let server_task = async move {
            let mut server_muxer = YamuxMuxer::new_server(server.compat());
            let mut server_muxer_control = server_muxer.control();

            let poll_task = tokio::spawn(async move {
                loop {
                    server_muxer.next_stream().await.unwrap();
                }
            });

            let accept_task = tokio::spawn(async move {
                println!("server: accepting substream");
                let fut = server_muxer_control.accept_substream("stream 0".to_string());
                fut.await.unwrap();
                println!("server: remote created substream");
            });

            _ = tokio::join!(poll_task, accept_task);
        };

        let _ = tokio::join!(client_task, server_task);
    }
}
