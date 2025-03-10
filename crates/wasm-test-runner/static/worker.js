import * as Comlink from "https://unpkg.com/comlink/dist/esm/comlink.mjs";
import init_wasm, * as wasm from "./generated/tlsn_wasm.js";

class TestWorker {
    async init() {
        try {
            console.log("initializing wasm");
            await init_wasm();
            await wasm.initialize({ level: "Debug" }, navigator.hardwareConcurrency);
        } catch (e) {
            console.error(e);
            throw e;
        }
    }

    async run() {
        let promises = [];
        for (const [name, func] of Object.entries(wasm)) {
            if (name.startsWith("test_") && (typeof func === 'function')) {
                promises.push((async () => {
                    console.log("running test", name);
                    const start = performance.now();
                    try {
                        await func();
                    } catch (error) {
                        return {
                            name: name,
                            passed: false,
                            error: error.toString(),
                        }
                    }

                    const duration_secs = (performance.now() - start) / 1000;
                    console.log(`Test ${name} passed in ${duration_secs} seconds`);
                    return {
                        name: name,
                        passed: true,
                        duration_secs,
                    }
                })());
            }
        }
        return Promise.all(promises);
    }
}

const worker = new TestWorker();

Comlink.expose(worker);
