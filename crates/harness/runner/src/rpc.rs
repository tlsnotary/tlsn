use std::{
    io::{self, ErrorKind},
    net::Ipv4Addr,
    time::Duration,
};

use chromiumoxide::Page;
use serio::{SinkExt, stream::IoStreamExt};
use tokio::net::TcpStream;

use harness_core::{
    bench::BenchOutput,
    rpc::{BenchCmd, Cmd, CmdOutput, Result, RpcError, TestCmd},
    test::TestOutput,
};

type Framed = serio::Framed<
    tokio_util::codec::Framed<TcpStream, tokio_util::codec::LengthDelimitedCodec>,
    serio::codec::Bincode,
>;

const RETRY_DELAY: usize = 50;
const MAX_RETRIES: usize = 10;

pub(crate) struct Rpc(Inner);

enum Inner {
    Native { io: Framed },
    Browser { page: Page },
}

impl Rpc {
    pub async fn new_native(addr: (Ipv4Addr, u16)) -> io::Result<Self> {
        let mut retries = 0;
        let stream = loop {
            match TcpStream::connect(addr).await {
                Ok(stream) => break stream,
                Err(e) if e.kind() == ErrorKind::ConnectionRefused => {
                    tokio::time::sleep(Duration::from_millis(RETRY_DELAY as u64)).await;
                    retries += 1;
                    if retries > MAX_RETRIES {
                        return Err(e);
                    }
                }
                Err(e) => return Err(e),
            }
        };

        let io = serio::Framed::new(
            tokio_util::codec::LengthDelimitedCodec::builder().new_framed(stream),
            serio::codec::Bincode,
        );

        Ok(Self(Inner::Native { io }))
    }

    pub fn new_browser(page: Page) -> Self {
        Self(Inner::Browser { page })
    }

    pub async fn get_tests(&mut self) -> io::Result<Result<Vec<String>>> {
        let output = match &mut self.0 {
            Inner::Native { io } => {
                io.send(Cmd::GetTests).await?;
                io.expect_next::<Result<CmdOutput>>().await?
            }
            Inner::Browser { page } => browser_cmd(page, Cmd::GetTests).await?,
        };

        Ok(match output {
            Ok(output) => output.try_into_get_tests().map_err(RpcError::from),
            Err(e) => Err(e),
        })
    }

    pub async fn test(&mut self, test: TestCmd) -> io::Result<Result<TestOutput>> {
        let output = match &mut self.0 {
            Inner::Native { io } => {
                io.send(Cmd::Test(test)).await?;
                io.expect_next::<Result<CmdOutput>>().await?
            }
            Inner::Browser { page } => browser_cmd(page, Cmd::Test(test)).await?,
        };

        Ok(match output {
            Ok(output) => output.try_into_test().map_err(RpcError::from),
            Err(e) => Err(e),
        })
    }

    pub async fn bench(&mut self, bench: BenchCmd) -> io::Result<Result<BenchOutput>> {
        let output = match &mut self.0 {
            Inner::Native { io } => {
                io.send(Cmd::Bench(bench)).await?;
                io.expect_next::<Result<CmdOutput>>().await?
            }
            Inner::Browser { page } => browser_cmd(page, Cmd::Bench(bench)).await?,
        };

        Ok(match output {
            Ok(output) => output.try_into_bench().map_err(RpcError::from),
            Err(e) => Err(e),
        })
    }
}

async fn browser_cmd(page: &Page, cmd: Cmd) -> io::Result<Result<CmdOutput>> {
    page.evaluate(format!(
        r#"
            (async () => {{
                return await window.executor.call(JSON.parse('{cmd}'));
            }})();
        "#,
        cmd = serde_json::to_string(&cmd).unwrap()
    ))
    .await
    .map_err(io::Error::other)?
    .into_value()
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
