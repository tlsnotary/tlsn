use std::{fmt::Display, pin::Pin};

use futures_plex::{DuplexStream, duplex};
use tlsn_sdk_core::{Binary, IoProvider, Manifest, Plugin, Runtime, Wasmtime};
use tlsn_server_fixture::bind;

#[test]
fn test_plugin() {
    futures::executor::block_on(async {
        let plugin = include_bytes!("../../sdk-plugin-test/sdk_plugin_test-component.wasm");

        let plugin = Plugin {
            manifest: Manifest {},
            binary: Binary(plugin.to_vec()),
        };

        let (server_io_0, server_io_1) = duplex(1024);
        let (io_0, io_1) = duplex(1024);

        let mut rt_p = Runtime::new(
            Wasmtime::new(),
            DummyIo {
                server_io: Some(server_io_0),
                io: Some(io_0),
            },
        );

        let mut rt_v = Runtime::new(
            Wasmtime::new(),
            DummyIo {
                server_io: None,
                io: Some(io_1),
            },
        );

        let server_fut = bind(server_io_1);
        futures::join!(
            async {
                let output = rt_p.run_plugin(&plugin, &[0]).await;
            },
            async {
                let output = rt_v.run_plugin(&plugin, &[1]).await;
            },
            async {
                server_fut.await.unwrap();
            },
        );
    });
}

pub struct DummyIo {
    server_io: Option<DuplexStream>,
    io: Option<DuplexStream>,
}

#[derive(Debug)]
pub struct Error;

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error")
    }
}
impl std::error::Error for Error {}

impl IoProvider for DummyIo {
    type Io = DuplexStream;
    type Error = Error;

    fn connect_server(
        &mut self,
        _name: &tlsn::connection::ServerName,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Io, Self::Error>> + Send>> {
        let io = self.server_io.take().unwrap();
        Box::pin(async move { Ok(io) })
    }

    fn connect_peer(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Io, Self::Error>> + Send>> {
        let io = self.io.take().unwrap();
        Box::pin(async move { Ok(io) })
    }
}
