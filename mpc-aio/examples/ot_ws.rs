use mpc_aio::ot::*;
use mpc_core::ot::{ChaChaAesOtReceiver, ChaChaAesOtSender};
use mpc_core::Block;
use tokio;
use tokio::net::UnixStream;

async fn ot_receive(stream: UnixStream) {
    println!("Receiver: Trying to connect");

    let mut ws_stream = tokio_tungstenite::accept_async(stream)
        .await
        .expect("Receiver: Error during the websocket handshake occurred");

    let mut receiver = OtReceiver::new(ChaChaAesOtReceiver::default());

    println!("Receiver: Websocket connected");

    let choice = [false, false, true];

    println!("Receiver: Choices: {:?}", &choice);

    let values = receiver.receive(&mut ws_stream, &choice).await.unwrap();

    println!("Receiver: Received: {:?}", values);
}

async fn ot_send(stream: UnixStream) {
    println!("Sender: Trying to connect");

    let (mut ws_stream, _) = tokio_tungstenite::client_async("ws://local/ot", stream)
        .await
        .expect("Sender: Error during the websocket handshake occurred");

    println!("Sender: Websocket connected");

    let mut sender = OtSender::new(ChaChaAesOtSender::default());

    let messages = [
        [Block::new(0), Block::new(1)],
        [Block::new(2), Block::new(3)],
        [Block::new(4), Block::new(5)],
    ];

    println!("Sender: Meesages: {:?}", &messages);

    let _ = sender.send(&mut ws_stream, &messages).await;
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
