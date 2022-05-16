use clap;
use clap::{ArgEnum, Parser, Subcommand};
use futures::{AsyncRead, AsyncWrite};
use mpc_aio::ot::{
    ExtOTReceive, ExtOTSend, ExtReceiver, ExtSender, OTReceive, OTSend, Receiver, Sender,
};
use mpc_core::ot::{ExtReceiverCore, ExtSenderCore, ReceiverCore, SenderCore};
use mpc_core::Block;
use rand::{thread_rng, Rng};
use tokio;
use tokio::net::{TcpListener, UnixStream};
use tracing::{info, instrument};
use tracing_subscriber;
use ws_stream_tungstenite::WsStream;

#[derive(Subcommand, Debug)]
enum Mode {
    Server {
        #[clap(long)]
        host: std::net::IpAddr,
        #[clap(long)]
        port: usize,
        #[clap(arg_enum)]
        cmd: Command,
    },
    Client {
        #[clap(long, value_hint = clap::ValueHint::Url)]
        url: String,
        #[clap(arg_enum)]
        cmd: Command,
    },
    Local,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, ArgEnum, Debug)]
enum Command {
    Send,
    Receive,
}

#[derive(Parser, Debug)]
struct Cli {
    #[clap(subcommand)]
    mode: Mode,
    #[clap(short = 'n', long, default_value = "5")]
    count: usize,
    #[clap(short = 'c', long, multiple_values(true))]
    choice: Option<Vec<bool>>,
    #[clap(long)]
    extended: bool,
}

#[instrument(skip(ws, choice))]
async fn receive<S: AsyncWrite + AsyncRead + Send + Unpin>(
    ws: async_tungstenite::WebSocketStream<S>,
    choice: Vec<bool>,
    extended: bool,
) {
    let stream = WsStream::new(ws);

    info!("Choosing {:?}", choice);

    let values = if extended {
        let mut receiver = ExtReceiver::new(ExtReceiverCore::new(choice.len()), stream);
        receiver.receive(&choice).await.unwrap()
    } else {
        let mut receiver = Receiver::new(ReceiverCore::new(choice.len()), stream);
        receiver.receive(&choice).await.unwrap()
    };

    info!("Received {:?}", values);
}

#[instrument(skip(ws, values))]
async fn send<S: AsyncWrite + AsyncRead + Send + Unpin>(
    ws: async_tungstenite::WebSocketStream<S>,
    values: Vec<[Block; 2]>,
    extended: bool,
) {
    let stream = WsStream::new(ws);

    if extended {
        let mut sender = ExtSender::new(ExtSenderCore::new(values.len()), stream);
        let _ = sender.send(&values).await;
    } else {
        let mut sender = Sender::new(SenderCore::new(values.len()), stream);
        let _ = sender.send(&values).await;
    }

    info!("Sent {:?}", values);
}

#[instrument]
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let args = Cli::parse();

    let mut rng = thread_rng();

    let choice: Vec<bool> = match args.choice {
        Some(choice) => choice,
        _ => (0..args.count).map(|_| rng.gen::<bool>()).collect(),
    };

    let values: Vec<[Block; 2]> = (0..choice.len())
        .map(|i| [Block::new(i as u128 * 2), Block::new((i as u128 * 2) + 1)])
        .collect();

    match args.mode {
        Mode::Client { url, cmd } => {
            let (ws, _) = async_tungstenite::tokio::connect_async(url).await.unwrap();
            info!("Connected");
            match cmd {
                Command::Receive => {
                    receive(ws, choice, args.extended).await;
                }
                Command::Send => {
                    send(ws, values, args.extended).await;
                }
            }
        }
        Mode::Server { host, port, cmd } => {
            let socket = TcpListener::bind(format!("{}:{}", host, port))
                .await
                .unwrap();
            let (stream, addr) = socket.accept().await.unwrap();
            info!("Received connection from {:?}", addr);
            let ws = async_tungstenite::tokio::accept_async(stream)
                .await
                .unwrap();
            match cmd {
                Command::Receive => {
                    receive(ws, choice, args.extended).await;
                }
                Command::Send => {
                    send(ws, values, args.extended).await;
                }
            }
        }
        Mode::Local => {
            let (unix_s, unix_r) = UnixStream::pair().unwrap();

            let (ws_s, ws_r) = tokio::join!(
                tokio::spawn(async move {
                    async_tungstenite::tokio::accept_async(unix_s)
                        .await
                        .unwrap()
                }),
                tokio::spawn(async move {
                    let (ws_r, _) =
                        async_tungstenite::tokio::client_async("ws://localhost/ot", unix_r)
                            .await
                            .unwrap();
                    ws_r
                })
            );

            let send = send(ws_s.unwrap(), values, args.extended);
            let receive = receive(ws_r.unwrap(), choice, args.extended);
            let _ = tokio::join!(
                tokio::spawn(async move { send.await }),
                tokio::spawn(async move { receive.await })
            );
        }
    }
}
