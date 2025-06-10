use harness_core::{ExecutorConfig, Id};
use harness_executor::Executor;
use serio::{Framed, SinkExt, StreamExt, codec::Bincode};
use tokio::net::TcpListener;
use tokio_util::codec::LengthDelimitedCodec;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let config = std::env::var("CONFIG").expect("CONFIG env var must be set");

    let config: ExecutorConfig = serde_json::from_str(&config)?;

    let rpc_addr = match config.id() {
        Id::Zero => config.network().rpc_0,
        Id::One => config.network().rpc_1,
    };

    let listener = TcpListener::bind(rpc_addr).await?;
    let (stream, _) = listener.accept().await?;

    let mut io = Framed::new(LengthDelimitedCodec::builder().new_framed(stream), Bincode);

    let executor = Executor::new(config);
    while let Some(cmd) = io.next().await.transpose()? {
        io.send(executor.process(cmd).await).await?;
    }

    Ok(())
}
