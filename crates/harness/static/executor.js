import * as Comlink from "./comlink.mjs";
import initWasm, * as wasm from "./generated/harness_executor.js";

class Executor {
    executor;

    async init(config) {
        try {
            console.log("loading wasm");
            await initWasm();
            console.log("wasm loaded");
            console.log("initializing wasm");
            await wasm.initialize({ thread_count: navigator.hardwareConcurrency });
            console.log("wasm initialized");
            console.log("initializing executor");
            this.executor = new wasm.WasmExecutor(config);
            console.log("executor initialized");
        } catch (e) {
            console.error(e);
            throw e;
        }
    }

    async call(cmd) {
        let panicCallback;
        const panicPromise = new Promise((resolve, _) => {
            panicCallback = resolve;
        });
        const callPromise = this.executor.call(cmd, panicCallback);

        return await Promise.race([callPromise, panicPromise]);
    }
}

const executor = new Executor();

Comlink.expose(executor);
