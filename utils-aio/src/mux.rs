use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
};

use async_trait::async_trait;
use futures::{
    channel::{mpsc, oneshot},
    stream_select, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, Future, SinkExt,
    StreamExt,
};
use yamux;

pub trait DuplexByteStream: AsyncWrite + AsyncRead {}

#[derive(Debug, thiserror::Error)]
pub enum MuxerError {
    #[error("Connection error occurred: {0}")]
    ConnectionError(String),
    #[error("IO error")]
    IOError(#[from] std::io::Error),
    #[error("Duplicate stream id: {0:?}")]
    DuplicateStreamId(String),
    #[error("Encountered internal error: {0:?}")]
    InternalError(String),
}

impl From<yamux::ConnectionError> for MuxerError {
    fn from(e: yamux::ConnectionError) -> Self {
        MuxerError::ConnectionError(e.to_string())
    }
}

#[async_trait]
pub trait MuxerControl: Clone {
    /// Opens a new substream with the remote using the provided id
    async fn get_substream(
        &mut self,
        id: String,
    ) -> Result<Box<dyn DuplexByteStream + Send>, MuxerError>;
}

impl DuplexByteStream for yamux::Stream {}

pub enum Event {
    ReceivedStream(yamux::Stream),
    OpenStream(String, oneshot::Sender<Result<yamux::Stream, MuxerError>>),
}

pub struct Client;
pub struct Server;

const MAX_COMMAND_BACKLOG: usize = 32;
const MAX_STREAM_BACKLOG: usize = 32;

pub fn new_mux_client<T: AsyncRead + AsyncWrite + Unpin>(
    socket: T,
) -> (
    Control,
    impl Future<Output = Result<(), MuxerError>>,
    impl Future<Output = Result<(), MuxerError>>,
) {
    let yamux_conn = yamux::Connection::new(socket, yamux::Config::default(), yamux::Mode::Client);
    let yamux_control = yamux_conn.control();

    let (stream_sender, stream_receiver) = mpsc::channel(MAX_STREAM_BACKLOG);
    let yamux_fut = run_connection(yamux_conn, stream_sender);

    let (muxer, control) = YamuxMuxer::<Client>::new(yamux_control, stream_receiver);
    let muxer_fut = muxer.run();

    (control, muxer_fut, yamux_fut)
}

pub fn new_mux_server<T: AsyncRead + AsyncWrite + Unpin>(
    socket: T,
) -> (
    Control,
    impl Future<Output = Result<(), MuxerError>>,
    impl Future<Output = Result<(), MuxerError>>,
) {
    let yamux_conn = yamux::Connection::new(socket, yamux::Config::default(), yamux::Mode::Server);
    let yamux_control = yamux_conn.control();

    let (stream_sender, stream_receiver) = mpsc::channel(MAX_STREAM_BACKLOG);
    let yamux_fut = run_connection(yamux_conn, stream_sender);

    let (muxer, control) = YamuxMuxer::<Server>::new(yamux_control, stream_receiver);
    let muxer_fut = muxer.run();

    (control, muxer_fut, yamux_fut)
}

async fn run_connection<T: AsyncRead + AsyncWrite + Unpin>(
    mut conn: yamux::Connection<T>,
    mut sender: mpsc::Sender<Event>,
) -> Result<(), MuxerError> {
    while let Some(stream) = conn.next_stream().await? {
        sender
            .send(Event::ReceivedStream(stream))
            .await
            .map_err(|_| MuxerError::InternalError("Failed to send new stream".to_string()))?;
    }
    Ok(())
}

pub struct YamuxMuxer<M> {
    _mode: PhantomData<M>,
    yamux_control: yamux::Control,
    yamux_streams: mpsc::Receiver<Event>,
    stream_ids: HashSet<String>,
    control_receiver: mpsc::Receiver<Event>,
    pending_accept: HashMap<String, oneshot::Sender<Result<yamux::Stream, MuxerError>>>,
    buffer_pending: HashMap<String, yamux::Stream>,
}

#[derive(Clone)]
pub struct Control {
    sender: mpsc::Sender<Event>,
}

#[async_trait]
impl MuxerControl for Control {
    async fn get_substream(
        &mut self,
        id: String,
    ) -> Result<Box<dyn DuplexByteStream + Send>, MuxerError> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Event::OpenStream(id, sender))
            .await
            .map_err(|_| MuxerError::InternalError("Failed to get substream".to_string()))?;

        let stream = receiver
            .await
            .map_err(|_| MuxerError::InternalError("Failed to get substream".to_string()))?;

        stream.map(|stream| Box::new(stream) as Box<dyn DuplexByteStream + Send>)
    }
}

impl<M> YamuxMuxer<M> {
    pub fn new(control: yamux::Control, streams: mpsc::Receiver<Event>) -> (Self, Control) {
        let (control_sender, control_receiver) = mpsc::channel(MAX_COMMAND_BACKLOG);

        (
            Self {
                _mode: PhantomData,
                yamux_control: control,
                yamux_streams: streams,
                control_receiver,
                stream_ids: HashSet::default(),
                pending_accept: HashMap::default(),
                buffer_pending: HashMap::default(),
            },
            Control {
                sender: control_sender,
            },
        )
    }
}

impl YamuxMuxer<Client> {
    pub async fn run(mut self) -> Result<(), MuxerError> {
        let mut events = stream_select!(self.yamux_streams, self.control_receiver);

        loop {
            match events.next().await {
                Some(Event::OpenStream(id, sender)) => {
                    // Check if a stream has been opened with this id before
                    if self.stream_ids.contains(&id) {
                        _ = sender.send(Err(MuxerError::DuplicateStreamId(id)));
                        continue;
                    }

                    // Insert stream id into set to avoid duplicates
                    self.stream_ids.insert(id.clone());

                    // Await opening a stream, this means we can only open 1 stream at a time.
                    let mut stream = self
                        .yamux_control
                        .open_stream()
                        .await
                        .map_err(MuxerError::from);

                    // If successful, fire off our application specific stream id to the remote
                    if let Ok(stream) = stream.as_mut() {
                        stream.write_all(format!("{}\n", &id).as_bytes()).await?;
                    }

                    // Return result back to caller
                    _ = sender.send(stream);
                }
                Some(Event::ReceivedStream(_)) => {
                    return Err(MuxerError::InternalError(
                        "Remote opened a stream unexpectedly".to_string(),
                    ))
                }
                None => {
                    return Err(MuxerError::InternalError(
                        "Muxer task ended unexpectedly".to_string(),
                    ))
                }
            }
        }
    }
}

impl YamuxMuxer<Server> {
    pub async fn run(mut self) -> Result<(), MuxerError> {
        let mut events = stream_select!(self.yamux_streams, self.control_receiver);

        loop {
            match events.next().await {
                Some(Event::OpenStream(id, sender)) => {
                    // Check if a stream has been opened with this id before
                    if self.stream_ids.contains(&id) {
                        _ = sender.send(Err(MuxerError::DuplicateStreamId(id)));
                        continue;
                    }

                    // Check internal buffer to see if we've already received the stream from
                    // the remote
                    if let Some(stream) = self.buffer_pending.remove(&id) {
                        self.stream_ids.insert(id);
                        let _ = sender.send(Ok(stream));
                    } else {
                        // If remote hasn't opened stream yet, insert into pending buffer
                        self.pending_accept.insert(id, sender);
                    }
                }
                Some(Event::ReceivedStream(stream)) => {
                    // Read stream id sent by remote
                    let mut stream_id = String::new();
                    let mut reader = futures::io::BufReader::new(stream);
                    reader.read_line(&mut stream_id).await?;
                    _ = stream_id.pop();
                    let stream = reader.into_inner();

                    // Check if we're already expecting this stream and return to caller,
                    // otherwise insert it into buffer
                    if let Some(sender) = self.pending_accept.remove(&stream_id) {
                        _ = sender.send(Ok(stream));
                    } else {
                        // the size of this buffer is bounded by the configuration of yamux (max open streams)
                        self.buffer_pending.insert(stream_id, stream);
                    }
                }
                None => {
                    return Err(MuxerError::InternalError(
                        "Muxer task ended unexpectedly".to_string(),
                    ))
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tokio::io::duplex;
    use tokio_util::compat::TokioAsyncReadCompatExt;

    #[tokio::test]
    async fn test_open_stream() {
        let (client, server) = duplex(1024);

        let (mut client_control, client_muxer_fut, client_yamux_fut) =
            new_mux_client(client.compat());
        let (mut server_control, server_muxer_fut, server_yamux_fut) =
            new_mux_server(server.compat());

        let _ = tokio::spawn(client_muxer_fut);
        let _ = tokio::spawn(client_yamux_fut);
        let _ = tokio::spawn(server_muxer_fut);
        let _ = tokio::spawn(server_yamux_fut);

        _ = client_control
            .get_substream("test".to_string())
            .await
            .unwrap();

        _ = server_control
            .get_substream("test".to_string())
            .await
            .unwrap();
    }
}
