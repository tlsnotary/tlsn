import * as Comlink from "https://unpkg.com/comlink/dist/esm/comlink.mjs";

const worker = Comlink.wrap(new Worker("worker.js", { type: "module" }));

window.worker = worker;
