import * as Comlink from "./comlink.mjs";

import init, { wasm_main, initThreadPool, init_logging } from './tlsn_benches_browser_wasm.js';

class Worker {
  async init() {
    try {
      await init();
      // Tracing may interfere with the benchmark results. We should enable it only for debugging.
      // init_logging({
      //   level: 'Debug',
      //   crate_filters: undefined,
      //   span_events: undefined,
      // });
      await initThreadPool(navigator.hardwareConcurrency);
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
      await wasm_main(
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

const worker = new Worker();

Comlink.expose(worker);