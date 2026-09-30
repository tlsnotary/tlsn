// Browser-side smoke assertions. Loaded by smoke.mjs through the local server
// and executed in the context of the built package.

import init, { Prover, Verifier, compute_reveal } from "./tlsn_wasm.js";

function proverConfig() {
    return {
        server_name: "example.com",
        mode: "Mpc",
        max_sent_data: 1024,
        max_recv_data: 1024,
        network: "Bandwidth",
    };
}

function verifierConfig() {
    return { max_sent_data: 1024, max_recv_data: 1024 };
}

const result = { ok: false, checks: {}, error: null };

(async () => {
    try {
        await init();
        result.checks.init = true;

        result.checks.proverConstruct = !!new Prover(proverConfig());
        result.checks.verifierConstruct = !!new Verifier(verifierConfig());

        const sent = new TextEncoder().encode(
            "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        );
        const recv = new TextEncoder().encode(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        );
        result.checks.computeReveal = compute_reveal(sent, recv, []) != null;

        result.ok = true;
    } catch (err) {
        result.error = String((err && err.stack) || err);
    } finally {
        window.__smoke = result;
    }
})();
