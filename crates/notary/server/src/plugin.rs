use std::path::Path;

use extism::{convert::Json, *};
use eyre::Result;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::config::PluginProperties;

#[derive(Serialize,Deserialize, ToBytes, FromBytes, Debug)]
#[encoding(Json)]
struct Output {
    count: i32,
}

host_fn!(add_extra(count: Output) -> Output {
    Ok(Output { count: count.count + 1 })
});

pub fn run_plugin(config: PluginProperties) {
    if !config.enabled {
        info!("Plugin is disabled, skipping execution");
        return;
    }

    let path = Wasm::file(Path::new(&config.path.unwrap()));
    let manifest = Manifest::new([path]);
    let mut plugin = PluginBuilder::new(manifest)
        .with_wasi(false)
        .with_function("add_extra", [PTR], [PTR], UserData::new(()), add_extra)
        .build()
        .unwrap();

    info!("Loaded plugin");
    let res = plugin.call::<&str, Output>("count_vowels", "Count!").unwrap();
    info!("Plugin response: {:?}", res);
}
