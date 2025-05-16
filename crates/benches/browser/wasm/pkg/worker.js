import * as Comlink from "./comlink.mjs";

import init_wasm, * as wasm from './tlsn_benches_browser_wasm.js';

class BenchWorker {
  async init() {
    try {
      await init_wasm();
      // Using Error level since excessive logging may interfere with the
      // benchmark results. 
      await wasm.initialize_bench({ level: "Error" }, navigator.hardwareConcurrency);
    } catch (e) {
      console.error(e);
      throw e;
    }
  }

  async run(
    ws_ip,
    ws_port,
    wasm_to_server_port,
    wasm_to_verifier_port,
    wasm_to_native_port
  ) {
    try {
      await wasm.wasm_main(
        ws_ip,
        ws_port,
        wasm_to_server_port,
        wasm_to_verifier_port,
        wasm_to_native_port);
    } catch (e) {
      console.error(e);
      throw e;
    }
  }
}

const worker = new BenchWorker();

Comlink.expose(worker);