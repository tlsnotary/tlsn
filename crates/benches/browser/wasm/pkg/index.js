import * as Comlink from "./comlink.mjs";

async function init() {
    const worker = Comlink.wrap(new Worker("worker.js", { type: "module" }));
    window.worker = worker;
}
init();
