use serde::{Deserialize, Serialize};
use wasmtime::{component::{bindgen, Component, HasSelf, Linker}, Config, Engine, Store};

const WASM_PLUGIN_PATH: &str = "../../target/wasm32-unknown-unknown/release/wasmtime_plugin_component.wasm";

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
        println!("Id received from plugin: {id}");
        serde_json::to_vec(&format!("Hello from host {}", id)).unwrap()
    }

    async fn write(&mut self, payload: Vec<u8>) -> Vec<u8> {
        let payload: String = serde_json::from_slice(&payload).unwrap();
        println!("Payload received from plugin: {payload}");
        let success = true;
        serde_json::to_vec(&success).unwrap()
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

    let mut store = Store::new(&engine, HostState {});

    let plugin = Plugin::instantiate_async(&mut store, &component, &linker).await?;

    let input = Input { id: 0 };
    println!("Input: {:?}", input);

    let input_bytes = serde_json::to_vec(&input)?;
    let res_byte = plugin.call_main(&mut store, &input_bytes).await?;
    let res: Output = serde_json::from_slice(&res_byte)?;

    println!("Output: {:?}", res);

    Ok(())
}
