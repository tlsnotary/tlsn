use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use async_trait::async_trait;

use futures::{channel::oneshot, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, Future};
use utils_aio::{
    duplex::DuplexByteStream,
    mux::{MuxControl, MuxerError},
};
use xtra::prelude::*;

pub struct OpenStream {
    id: String,
    /// the Client who initiated opening a new stream is waiting to receive
    /// the stream via this oneshot channel
    sender: oneshot::Sender<Result<yamux::Stream, MuxerError>>,
}
pub struct ReceivedStream(Result<yamux::Stream, yamux::ConnectionError>);

pub enum Mode {
    Client,
    Server,
}

pub struct YamuxConfig {
    mode: Mode,
    yamux_config: yamux::Config,
}

impl YamuxConfig {
    pub fn default_client() -> Self {
        Self {
            mode: Mode::Client,
            yamux_config: yamux::Config::default(),
        }
    }

    pub fn default_server() -> Self {
        Self {
            mode: Mode::Server,
            yamux_config: yamux::Config::default(),
        }
    }
}

/// Stream multiplexer which uses the yamux protocol with a small tweak on top to provide
/// configurable unique stream ids
#[derive(xtra::Actor)]
pub struct YamuxMuxer {
    config: YamuxConfig,
    control: yamux::Control,
    /// ids of streams already opened by the Client
    stream_ids: HashSet<String>,
    /// The Server's buffer containing the streams which the Client opened and is ready to use
    /// but the Server is not ready to use yet
    /// For the Client it is always empty
    /// The size of this buffer is bounded by the configuration of yamux (max open streams)
    stream_buffer: HashMap<String, yamux::Stream>,
    /// The Server's buffer containing a mapping:
    /// - the id of the stream which the Client is expected to open and
    /// - the channel on which a task is waiting to receive the stream
    /// For the Client it is always empty since the Client is the one who always
    /// initiates the opening of new streams
    pending_buffer: HashMap<String, oneshot::Sender<Result<yamux::Stream, MuxerError>>>,
}

impl YamuxMuxer {
    /// Creates a new actor
    ///
    /// Returns actor and yamux connection future (which has to be polled to make progress)
    pub fn new<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
        addr: Address<Self>,
        socket: T,
        config: YamuxConfig,
    ) -> (Self, impl Future<Output = ()> + Send) {
        let mut connection = yamux::Connection::new(
            socket,
            config.yamux_config.clone(),
            match config.mode {
                Mode::Client => yamux::Mode::Client,
                Mode::Server => yamux::Mode::Server,
            },
        );
        let control = connection.control();
        (
            Self {
                config,
                control,
                stream_ids: HashSet::default(),
                stream_buffer: HashMap::default(),
                pending_buffer: HashMap::default(),
            },
            async move {
                loop {
                    match connection.next_stream().await {
                        Ok(stream) => match stream {
                            Some(stream) => {
                                // Forward streams opened by the remote to YamuxMuxer
                                if addr
                                    .send(ReceivedStream(Ok(stream)))
                                    .priority(1)
                                    .await
                                    .is_err()
                                {
                                    // Shutdown if YamuxMuxer drops
                                    break;
                                }
                            }
                            None => {
                                // Connection shutdown gracefully, shutdown loop
                                break;
                            }
                        },
                        Err(e) => {
                            // Forward error to actor then shutdown
                            _ = addr.send(ReceivedStream(Err(e))).await;
                            break;
                        }
                    }
                }
            },
        )
    }
}

#[async_trait]
impl Handler<OpenStream> for YamuxMuxer {
    type Return = ();

    async fn handle(&mut self, msg: OpenStream, _ctx: &mut Context<Self>) {
        // Check if a stream has been opened with this id before
        if self.stream_ids.contains(&msg.id) {
            _ = msg.sender.send(Err(MuxerError::DuplicateStreamId(msg.id)));
            return;
        }

        // Insert stream id into set to avoid duplicates
        self.stream_ids.insert(msg.id.clone());

        match self.config.mode {
            Mode::Client => {
                // Await opening a stream
                let mut stream = self
                    .control
                    .open_stream()
                    .await
                    .map_err(|e| MuxerError::InternalError(e.to_string()));

                // If successful, fire off our application specific stream id to the remote
                if let Ok(stream) = stream.as_mut() {
                    if stream
                        .write_all(format!("{}\n", &msg.id).as_bytes())
                        .await
                        .is_err()
                    {
                        // If error sending stream id, return it to caller
                        _ = msg.sender.send(Err(MuxerError::InternalError(
                            "Error sending stream id".to_string(),
                        )));
                        return;
                    };
                }

                // Return result back to caller
                _ = msg.sender.send(stream);
            }
            Mode::Server => {
                // Check internal buffer to see if we've already received the stream from
                // the remote
                if let Some(stream) = self.stream_buffer.remove(&msg.id) {
                    _ = msg.sender.send(Ok(stream));
                } else {
                    // If remote hasn't opened stream yet, insert into pending buffer
                    self.pending_buffer.insert(msg.id, msg.sender);
                }
            }
        }
    }
}

/// The controller of [YamuxMuxer]
#[derive(Clone)]
pub struct YamuxMuxControl(Address<YamuxMuxer>);

impl YamuxMuxControl {
    pub fn new(addr: Address<YamuxMuxer>) -> Self {
        Self(addr)
    }

    pub fn inner(self) -> Address<YamuxMuxer> {
        self.0
    }
}

#[async_trait]
impl MuxControl for YamuxMuxControl {
    async fn get_stream(
        &mut self,
        id: String,
    ) -> Result<Box<dyn DuplexByteStream + Send>, MuxerError> {
        let (sender, receiver) = oneshot::channel();
        self.0
            .send(OpenStream { id, sender })
            .await
            .map_err(|_| MuxerError::InternalError("Failed to get stream".to_string()))?;

        let stream = receiver
            .await
            .map_err(|_| MuxerError::InternalError("Failed to get stream".to_string()))?;

        stream.map(|stream| Box::new(stream) as Box<dyn DuplexByteStream + Send>)
    }
}

#[async_trait]
impl Handler<ReceivedStream> for YamuxMuxer {
    type Return = ();

    async fn handle(&mut self, msg: ReceivedStream, ctx: &mut Context<Self>) {
        let Ok(stream) = msg.0 else {
            // Yamux connection threw an error, we shutdown gracefully
            ctx.stop_self();
            return;
        };
        match self.config.mode {
            Mode::Client => {
                // The server should never open streams, shutdown if it does
                ctx.stop_self();
            }
            Mode::Server => {
                // Read stream id sent by remote
                let mut stream_id = String::new();
                let mut reader = futures::io::BufReader::new(stream);
                if let Err(_) =
                    tokio::time::timeout(Duration::from_secs(1), reader.read_line(&mut stream_id))
                        .await
                {
                    // The client should always send the stream id immediately, if not, we shutdown
                    ctx.stop_all();
                    return;
                }

                // pop newline character off id
                _ = stream_id.pop();
                // unwrap stream out of reader
                let stream = reader.into_inner();

                // Check if we're already expecting this stream and return to caller,
                // otherwise insert it into buffer
                if let Some(sender) = self.pending_buffer.remove(&stream_id) {
                    _ = sender.send(Ok(stream));
                } else {
                    // the size of this buffer is bounded by the configuration of yamux (max open streams)
                    self.stream_buffer.insert(stream_id, stream);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::AsyncReadExt;
    use tokio::io::duplex;
    use tokio_util::compat::TokioAsyncReadCompatExt;

    async fn new_pair() -> (Address<YamuxMuxer>, Address<YamuxMuxer>) {
        let (client_socket, server_socket) = duplex(1024);

        let (client_addr, client_mailbox) = Mailbox::unbounded();
        let (server_addr, server_mailbox) = Mailbox::unbounded();

        let (client_actor, client_fut) = YamuxMuxer::new(
            client_addr.clone(),
            client_socket.compat(),
            YamuxConfig::default_client(),
        );

        let (server_actor, server_fut) = YamuxMuxer::new(
            server_addr.clone(),
            server_socket.compat(),
            YamuxConfig::default_server(),
        );

        tokio::spawn(client_fut);
        tokio::spawn(server_fut);

        let client_addr = xtra::spawn_tokio(client_actor, (client_addr, client_mailbox));
        let server_addr = xtra::spawn_tokio(server_actor, (server_addr, server_mailbox));

        (client_addr, server_addr)
    }

    #[tokio::test]
    async fn test_open_stream() {
        let (client_addr, server_addr) = new_pair().await;

        let mut client_control = YamuxMuxControl::new(client_addr);
        let mut server_control = YamuxMuxControl::new(server_addr);

        let stream_id = "test_id".to_string();

        let mut client_stream = client_control.get_stream(stream_id.clone()).await.unwrap();
        let mut server_stream = server_control.get_stream(stream_id).await.unwrap();

        let msg = "test message".as_bytes();

        client_stream.write_all(msg).await.unwrap();
        server_stream.write_all(msg).await.unwrap();

        let mut received = vec![0u8; msg.len()];

        client_stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, msg);

        server_stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, msg);
    }

    #[tokio::test]
    async fn test_no_duplicates() {
        let (client_addr, server_addr) = new_pair().await;

        let mut client_control = YamuxMuxControl::new(client_addr);
        let mut server_control = YamuxMuxControl::new(server_addr);

        let stream_id = "test_id".to_string();

        let _ = client_control.get_stream(stream_id.clone()).await.unwrap();
        let err = client_control.get_stream(stream_id.clone()).await;

        assert!(matches!(err, Err(MuxerError::DuplicateStreamId(_))));

        let _ = server_control.get_stream(stream_id.clone()).await.unwrap();
        let err = server_control.get_stream(stream_id).await;

        assert!(matches!(err, Err(MuxerError::DuplicateStreamId(_))));
    }
}
