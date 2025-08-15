uniffi::setup_scaffolding!();

use std::time::Duration;

use android_logger::Config as LogConfig;
use async_std::future::{pending, timeout};
use log::{info, LevelFilter};
use serde::{Deserialize, Serialize};
use wasmtime::{component::{bindgen, Component, HasSelf, Linker}, Config, Engine, Store};

bindgen!({
    path: "../wasmtime-plugin/wit/world.wit",
    imports: {
        "read": async,
        "write": async,
    },
    exports: {
        "main": async,
    }
});

#[derive(Serialize, Debug)]
struct Input {
    id: u8
}

#[derive(Serialize, Deserialize, Debug)]
struct Output {
    result: bool
}

struct HostState {}

impl PluginImports for HostState {
    async fn read(&mut self, id: u8) -> Vec<u8> {
        info!("Id received from plugin: {id}");
        serde_json::to_vec(&format!("Hello from host {}", id)).unwrap()
    }

    async fn write(&mut self, payload: Vec<u8>) -> Vec<u8> {
        let payload: String = serde_json::from_slice(&payload).unwrap();
        info!("Payload received from plugin: {payload}");
        let success = true;
        serde_json::to_vec(&success).unwrap()
    }
}

#[uniffi::export]
async fn main(wasm_path: &str) {
    android_logger::init_once(
        LogConfig::default()
            .with_tag("RustWasmtime")
            .with_max_level(LevelFilter::Info)
    );

    info!("Starting wasmtime");

    let mut config = Config::new();
    config
        .async_support(true)
        .wasm_component_model_async(true);

    let engine = Engine::new(&config).unwrap();

    let component = Component::from_file(&engine, wasm_path).unwrap();
    let mut linker = Linker::new(&engine);
    
    Plugin::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state).unwrap();

    let mut store = Store::new(&engine, HostState {});

    let plugin = Plugin::instantiate_async(&mut store, &component, &linker).await.unwrap();

    let input = Input { id: 0 };
    info!("Input: {:.?}", input);

    // Sleep for 10s to test async capability on android host.
    info!("Sleeping for 10s...");
    let never = pending::<()>();
    timeout(Duration::from_millis(10000), never).await.unwrap_err();

    let input_bytes = serde_json::to_vec(&input).unwrap();
    let res_byte = plugin.call_main(&mut store, &input_bytes).await.unwrap();
    let res: Output = serde_json::from_slice(&res_byte).unwrap();

    info!("Output: {:?}", res);
}
