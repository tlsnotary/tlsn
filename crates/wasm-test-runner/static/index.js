import * as Comlink from "https://unpkg.com/comlink/dist/esm/comlink.mjs";

const testWorker = Comlink.wrap(new Worker("worker.js", { type: "module" }));

window.testWorker = testWorker;
