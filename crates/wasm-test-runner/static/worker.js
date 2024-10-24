import * as Comlink from "https://unpkg.com/comlink/dist/esm/comlink.mjs";
import init_wasm, { init_logging, initThreadPool } from "./generated/tlsn_wasm.js";

const module = await import("./generated/tlsn_wasm.js");

class TestWorker {
    async init() {
        try {
            await init_wasm();
            init_logging();
            console.log("initialized logging");
            await initThreadPool(8);
            console.log("initialized worker");
        } catch (e) {
            console.error(e);
            throw e;
        }
    }
    
    run() {
        let promises = [];
        for (const [name, func] of Object.entries(module)) {
            
            if(name.startsWith("test_") && (typeof func === 'function')) {
                promises.push(func().then(_ => { return {
                    name: name,
                    passed: true,
                } }).catch(error => { return {
                    name: name,
                    passed: false,
                    error: error.toString(),
                } }));
            }
        }
        return Promise.all(promises);
    }
}

const worker = new TestWorker();

Comlink.expose(worker);
