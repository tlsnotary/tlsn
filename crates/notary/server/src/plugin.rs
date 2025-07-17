use eyre::{eyre, Result};
use glob::glob;
use notary_common::Input;
use std::path::Path;
use tokio::{
    io::{AsyncRead, AsyncWrite},
};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::debug;

use std::io::{Read, Write};
use wasmer::Module;
use wasmer_wasix::{
    runners::{wasi::WasiRunner, RuntimeOrEngine},
    Pipe,
};

use crate::{types::NotaryGlobals, NotaryServerError};

pub fn get_plugin_names(dir: &str) -> Result<Vec<String>, NotaryServerError> {
    let names: Vec<String> = glob(&format!("{}/*.wasm", dir))
        .map_err(|e| eyre!("Failed to find wasm files in plugin directory: {}", e))?
        .filter_map(|path| {
            path.ok()?.file_stem()?.to_str().map(String::from)
        })
        .collect();

    if names.is_empty() {
        return Err(eyre!("No readable plugin files found in directory: {}", dir).into());
    }

    Ok(names)
}

pub async fn verifier_service<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    socket: T,
    notary_globals: NotaryGlobals,
    session_id: &str,
    plugin_name: &str,
) -> Result<(), NotaryServerError> {
    debug!(?session_id, "Starting verification...");

    let input = Input {
        socket: socket.compat(),
        timeout: notary_globals.notarization_config.timeout,
        max_sent_data: notary_globals.notarization_config.max_sent_data,
        max_recv_data: notary_globals.notarization_config.max_recv_data,
    };

    // Let's declare the Wasm module with the text representation.
    let wasm_bytes = std::fs::read(Path::new(&notary_globals.plugin_config.folder).join(format!("{}.wasm", plugin_name)))
        .map_err(|e| eyre!("Failed to read Wasm file: {}", e))?;

    // We need at least an engine to be able to compile the module.
    let engine = wasmer::Engine::default();

    debug!("Compiling module...");
    // Let's compile the Wasm module.
    let module = Module::new(&engine, &wasm_bytes[..]).map_err(|e| eyre!("Failed to compile Wasm module: {}", e))?;

    let msg = serde_json::to_string(&input)
        .map_err(|e| eyre!("Failed to serialize input: {}", e))?;
    debug!("Writing \"{}\" to the WASI stdin...", msg);
    let (mut stdin_sender, stdin_reader) = Pipe::channel();
    let (stdout_sender, mut stdout_reader) = Pipe::channel();

    // To write to the stdin
    writeln!(stdin_sender, "{}", msg)
        .map_err(|e| eyre!("Failed to write to WASI stdin: {}", e))?;

    {
        // Create a WASI runner. We use a scope to make sure the runner is dropped
        // as soon as we are done with it; otherwise, it will keep the stdout pipe
        // open.
        let mut runner = WasiRunner::new();

        // Configure the WasiRunner with the stdio pipes.
        runner
            .with_stdin(Box::new(stdin_reader))
            .with_stdout(Box::new(stdout_sender));

        // Now, run the module.
        debug!("Running module...");
        runner.run_wasm(
            RuntimeOrEngine::Engine(engine),
            "run",
            module,
            wasmer_types::ModuleHash::xxhash(wasm_bytes),
        ).map_err(|e| eyre!("Failed to run Wasm module: {}", e))?;
    }

    // To read from the stdout
    let mut buf = String::new();
    stdout_reader.read_to_string(&mut buf).map_err(|e| eyre!("Failed to read from WASI stdout: {}", e))?;
    debug!("Read \"{}\" from the WASI stdout!", buf.trim());

    Ok(())
}
