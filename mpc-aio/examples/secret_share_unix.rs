use mpc_aio::secret_share::{SecretShareMaster, SecretShareSlave};
use mpc_core::proto;
use mpc_core::secret_share::{SecretShare, SecretShareMessage};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{EncodedPoint, SecretKey};
use rand::thread_rng;
use std::time::Instant;
use tokio;
use tokio::net::UnixStream;
use tokio_util::codec::Framed;
use utils_aio::codec::ProstCodecDelimited;

async fn master(stream: UnixStream, point: EncodedPoint) -> SecretShare {
    println!("Master: Trying to connect");

    let stream = Framed::new(
        stream,
        ProstCodecDelimited::<SecretShareMessage, proto::secret_share::SecretShareMessage>::default(
        ),
    );

    let mut master = SecretShareMaster::new(stream);

    println!("Master: Connected");

    let share = master.run(&point).await.unwrap();

    println!("Master: {:?}", share);

    share
}

async fn slave(stream: UnixStream, point: EncodedPoint) -> SecretShare {
    println!("Slave: Trying to connect");

    let stream = Framed::new(
        stream,
        ProstCodecDelimited::<SecretShareMessage, proto::secret_share::SecretShareMessage>::default(
        ),
    );

    println!("Slave: Connected");

    let mut slave = SecretShareSlave::new(stream);

    let share = slave.run(&point).await.unwrap();

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
