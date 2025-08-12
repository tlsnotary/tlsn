use std::{pin::Pin, task::{Context, Waker}};

use anyhow::{Error};
use serde::{Deserialize, Serialize};
use tokio::{io::{AsyncWrite}, net::TcpStream};
use wasmtime::{component::{bindgen, Component, HasSelf, Linker, Resource, ResourceTable}, Config, Engine, Store, Result};

use component::wasmtime_plugin::io::{Host, HostNetworkIo};

const WASM_PLUGIN_PATH: &str = "../../target/wasm32-unknown-unknown/release/wasmtime_plugin_component.wasm";

bindgen!({
    path: "../wasmtime-plugin/wit/plugin.wit",
    imports: { 
        default: async | trappable,
    },
    exports: {
        default: async,
    },
    with: {
        "component:wasmtime-plugin/io/network-io": NetworkIo,
    },
});

#[derive(Serialize, Debug)]
struct Input {
    host: String,
    port: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct Output {
    result: bool
}

pub struct NetworkIo {
    inner: TcpStream
}

#[derive(Default)]
struct HostState {
    table: ResourceTable,
}

impl Host for HostState {}

impl HostNetworkIo for HostState {
    async fn new(&mut self, host: String, port: u32) -> Result<Resource<NetworkIo>> {
        let connection = TcpStream::connect(format!("{host}:{port}"))
            .await
            .map_err(|err| Error::msg(err))?;

        println!("Connection established");

        let id = self.table.push(NetworkIo { inner: connection })?;
        Ok(id)
    }

    async fn read(&mut self, network_io: Resource<NetworkIo>, max: u32) -> Result<Vec<u8>> {
        debug_assert!(!network_io.owned());

        println!("Trying to reads");

        let conn = self.table.get(&network_io)?;
        let mut buf = vec![0u8; max as usize];
        loop {
            conn.inner.readable().await?;
            match conn.inner.try_read(&mut buf) {
                Ok(0) => return Ok(Vec::new()),       // EOF
                Ok(n) => return Ok(buf[..n].to_vec()),// got bytes
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }

    async fn write(&mut self, network_io: Resource<NetworkIo>, bytes: Vec<u8>) -> Result<u32> {
        debug_assert!(!network_io.owned());

        println!("Trying to write");

        let conn = self.table.get(&network_io)?;
        let mut offset = 0;
        while offset < bytes.len() {
            conn.inner.writable().await?;
            match conn.inner.try_write(&bytes[offset..]) {
                Ok(0) => break,
                Ok(n) => offset += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(offset as u32)
    }

    async  fn shutdown(&mut self, network_io: Resource<NetworkIo>,) -> Result<()> {
        debug_assert!(!network_io.owned());

        println!("Trying to shut down");

        let conn = self.table.get_mut(&network_io)?;
        let mut context = Context::from_waker(Waker::noop());
        
        let _ = Pin::new(&mut conn.inner).poll_shutdown(&mut context);

        Ok(())
    }

    async fn drop(&mut self, network_io: Resource<NetworkIo>) -> Result<()> {
        debug_assert!(network_io.owned());

        println!("Trying to drop");

        self.table.delete(network_io)?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("Starting wasmtime");

    let mut config = Config::new();
    config
        .async_support(true)
        .wasm_component_model_async(true);

    let engine = Engine::new(&config)?;

    let component = Component::from_file(&engine, WASM_PLUGIN_PATH)?;
    let mut linker = Linker::new(&engine);
    
    Plugin::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)?;

    let mut store = Store::new(&engine, HostState::default());

    let plugin = Plugin::instantiate_async(&mut store, &component, &linker).await?;

    let input = Input { host: "0.0.0.0".into(), port: 7044 };
    println!("Inputs: {:?}", input);
    let input_bytes = serde_json::to_vec(&input)?;

    let res_byte = plugin.call_main(&mut store, &input_bytes).await?;
    let res: Output = serde_json::from_slice(&res_byte)?;

    println!("Output: {:?}", res);

    Ok(())
}
