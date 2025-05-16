import * as Comlink from "./comlink.mjs";

const benchWorker = Comlink.wrap(new Worker("worker.js", { type: "module" }));

window.benchWorker = benchWorker;