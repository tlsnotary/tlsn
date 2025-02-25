import * as Comlink from "https://unpkg.com/comlink/dist/esm/comlink.mjs";
import init_wasm, { initialize } from "./generated/tlsn_wasm.js";

const module = await import("./generated/tlsn_wasm.js");

class TestWorker {
    async init() {
        try {
            console.log("initializing wasm");
            await init_wasm();
            await initialize({ thread_count: navigator.hardwareConcurrency });
        } catch (e) {
            console.error(e);
            throw e;
        }
    }

    async run() {
        let promises = [];
        for (const [name, func] of Object.entries(module)) {
            if (name.startsWith("test_") && (typeof func === 'function')) {
                promises.push((async () => {
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
