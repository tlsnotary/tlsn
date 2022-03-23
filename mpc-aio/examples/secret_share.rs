use mpc_aio::secret_share::{AsyncSecretShareMaster, AsyncSecretShareSlave};
use mpc_core::secret_share::SecretShare;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{EncodedPoint, SecretKey};
use rand::thread_rng;
use std::time::Instant;
use tokio;
use tokio::net::UnixStream;

async fn master(stream: UnixStream, point: EncodedPoint) -> SecretShare {
    println!("Master: Trying to connect");

    let mut ws_stream = tokio_tungstenite::accept_async(stream)
        .await
        .expect("Master: Error during the websocket handshake occurred");

    let mut master = AsyncSecretShareMaster::new();

    println!("Master: Websocket connected");

    let share = master.run(&mut ws_stream, &point).await.unwrap();

    println!("Master: {:?}", share);

    share
}

async fn slave(stream: UnixStream, point: EncodedPoint) -> SecretShare {
    println!("Slave: Trying to connect");

    let (mut ws_stream, _) = tokio_tungstenite::client_async("ws://local/ss", stream)
        .await
        .expect("Slave: Error during the websocket handshake occurred");

    println!("Slave: Websocket connected");

    let mut slave = AsyncSecretShareSlave::new();

    let share = slave.run(&mut ws_stream, &point).await.unwrap();

    println!("Slave: {:?}", share);

    share
}

#[tokio::main]
async fn main() {
    let (unix_s, unix_r) = UnixStream::pair().unwrap();

    let master_point = SecretKey::random(&mut thread_rng())
        .public_key()
        .to_projective()
        .to_encoded_point(false);
    let slave_point = SecretKey::random(&mut thread_rng())
        .public_key()
        .to_projective()
        .to_encoded_point(false);

    let master = master(unix_s, master_point);
    let slave = slave(unix_r, slave_point);

    let t = Instant::now();
    let _ = tokio::join!(
        tokio::spawn(async move { master.await }),
        tokio::spawn(async move { slave.await })
    );
    println!("Took {:?}", t.elapsed());
}
