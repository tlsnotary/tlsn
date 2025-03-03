import * as Comlink from "https://unpkg.com/comlink/dist/esm/comlink.mjs";
import initWasm, * as wasm from "./generated/tlsn_harness.js";

class WasmWorker {
    async init() {
        try {
            console.log("initializing wasm");
            await initWasm();
            await wasm.initialize({ thread_count: navigator.hardwareConcurrency });
        } catch (e) {
            console.error(e);
            throw e;
        }
    }

    async runTestProver(config) {
        return await wasm.runTestProver(config);
    }

    async runTestVerifier(config) {
        return await wasm.runTestVerifier(config);
    }

    async runBench(bench) {
        return await wasm.runBench(bench);
    }
}

const worker = new WasmWorker();

Comlink.expose(worker);
