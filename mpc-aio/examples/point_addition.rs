use mpc_aio::point_addition::{PointAdditionMaster, PointAdditionSlave};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{EncodedPoint, SecretKey};
use rand::thread_rng;
use tokio;
use tokio::net::UnixStream;
use tracing::{info, instrument};
use tracing_subscriber;

#[instrument(skip(stream, point))]
async fn master(stream: UnixStream, point: EncodedPoint) {
    let mut master = PointAdditionMaster::new(stream);

    let share = master.run(&point).await.unwrap();

    info!("Master keyshare: {:?}", share);
}

#[instrument(skip(stream, point))]
async fn slave(stream: UnixStream, point: EncodedPoint) {
    let mut slave = PointAdditionSlave::new(stream);

    let share = slave.run(&point).await.unwrap();

    info!("Slave keyshare: {:?}", share);
}

#[instrument]
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    info!("Creating Unix Stream");
    let (unix_s, unix_r) = UnixStream::pair().unwrap();

    info!("Generating Master key");
    let master_point = SecretKey::random(&mut thread_rng())
        .public_key()
        .to_projective()
        .to_encoded_point(false);

    info!("Generating Slave key");
    let slave_point = SecretKey::random(&mut thread_rng())
        .public_key()
        .to_projective()
        .to_encoded_point(false);

    let master = master(unix_s, master_point);
    let slave = slave(unix_r, slave_point);

    let _ = tokio::join!(
        tokio::spawn(async move { master.await }),
        tokio::spawn(async move { slave.await })
    );
}
