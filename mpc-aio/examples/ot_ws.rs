use mpc_aio::ot::{OtReceive, OtReceiver, OtSend, OtSender};
use mpc_core::ot::{ChaChaAesOtReceiver, ChaChaAesOtSender, OtMessage};
use mpc_core::proto;
use mpc_core::Block;
use tokio;
use tokio::net::UnixStream;
use tokio_util::codec::Framed;
use utils_aio::codec::ProstCodecDelimited;
use ws_stream_tungstenite::WsStream;

async fn ot_receive(stream: UnixStream) {
    println!("Receiver: Trying to connect");

    let ws = async_tungstenite::tokio::accept_async(stream)
        .await
        .expect("Receiver: Error during the websocket handshake occurred");

    println!("Receiver: Websocket connected");

    let ws = WsStream::new(ws);

    let stream = Framed::new(
        ws,
        ProstCodecDelimited::<OtMessage, proto::ot::OtMessage>::default(),
    );

    let mut receiver = OtReceiver::new(ChaChaAesOtReceiver::default(), stream);

    let choice = vec![false, false, true];

    println!("Receiver: Choices: {:?}", &choice);

    let values = receiver.receive(&choice).await.unwrap();

    println!("Receiver: Received: {:?}", values);
}

async fn ot_send(stream: UnixStream) {
    println!("Sender: Trying to connect");

    let (ws, _) = async_tungstenite::tokio::client_async("ws://local/ot", stream)
        .await
        .expect("Sender: Error during the websocket handshake occurred");

    println!("Sender: Websocket connected");

    let ws = WsStream::new(ws);

    let stream = Framed::new(
        ws,
        ProstCodecDelimited::<OtMessage, proto::ot::OtMessage>::default(),
    );

    let mut sender = OtSender::new(ChaChaAesOtSender::default(), stream);

    let messages = [
        [Block::new(0), Block::new(1)],
        [Block::new(2), Block::new(3)],
        [Block::new(4), Block::new(5)],
    ];

    println!("Sender: Meesages: {:?}", &messages);

    let _ = sender.send(&messages).await;
}

#[tokio::main]
async fn main() {
    let (unix_s, unix_r) = UnixStream::pair().unwrap();

    let send = ot_send(unix_s);
    let receive = ot_receive(unix_r);

    let _ = tokio::join!(
        tokio::spawn(async move { send.await }),
        tokio::spawn(async move { receive.await })
    );
}
