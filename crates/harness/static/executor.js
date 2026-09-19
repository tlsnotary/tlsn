import * as Comlink from "./comlink.mjs";
import initWasm, * as wasm from "./generated/harness_executor.js";

class WebSocketIoChannel {
    constructor(socket) {
        this.socket = socket;
        this.queue = [];
        this.reader = null;

        socket.binaryType = "arraybuffer";
        socket.onmessage = ({ data }) => {
            const bytes = new Uint8Array(data);
            if (this.reader) {
                const reader = this.reader;
                this.reader = null;
                reader.resolve(bytes);
            } else {
                this.queue.push(bytes);
            }
        };
        socket.onclose = () => {
            if (this.reader) {
                const reader = this.reader;
                this.reader = null;
                reader.resolve(null);
            }
        };
        socket.onerror = () => {
            if (this.reader) {
                const reader = this.reader;
                this.reader = null;
                reader.reject(new Error("WebSocket error"));
            }
        };
    }

    read() {
        if (this.queue.length) return Promise.resolve(this.queue.shift());
        if (this.socket.readyState === WebSocket.CLOSED) return Promise.resolve(null);
        if (this.reader) return Promise.reject(new Error("concurrent read"));
        return new Promise((resolve, reject) => { this.reader = { resolve, reject }; });
    }

    write(data) {
        this.socket.send(data);
        return Promise.resolve();
    }

    close() {
        this.socket.close();
        return Promise.resolve();
    }

    isOpen() {
        return this.socket.readyState === WebSocket.OPEN;
    }
}

globalThis.connectIoChannel = (url) => new Promise((resolve, reject) => {
    const socket = new WebSocket(url);
    socket.onopen = () => resolve(new WebSocketIoChannel(socket));
    socket.onerror = () => reject(new Error(`failed to connect to ${url}`));
});

class Executor {
    executor;

    async init(config, loggingConfig) {
        try {
            console.log("loading wasm");
            await initWasm();
            console.log("wasm loaded");
            console.log("initializing wasm");
            await wasm.initialize(loggingConfig, navigator.hardwareConcurrency);
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
