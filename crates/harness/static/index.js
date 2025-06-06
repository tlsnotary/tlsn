import * as Comlink from "./comlink.mjs";

const executor = Comlink.wrap(new Worker("executor.js", { type: "module" }));

window.executor = executor;
