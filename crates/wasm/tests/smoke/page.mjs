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

        // Unknown config fields must be rejected at runtime, not silently
        // ignored, through the shipped package.
        let rejectedProver = false;
        try {
            new Prover({ ...proverConfig(), unknownOption: 4096 });
        } catch {
            rejectedProver = true;
        }
        result.checks.proverRejectsUnknown = rejectedProver;

        let rejectedVerifier = false;
        try {
            new Verifier({ ...verifierConfig(), unknownOption: 4096 });
        } catch {
            rejectedVerifier = true;
        }
        result.checks.verifierRejectsUnknown = rejectedVerifier;

        // Nested session options must be accepted...
        let acceptedNestedSession = false;
        try {
            new Prover({ ...proverConfig(), session: { max_num_streams: 4096 } });
            acceptedNestedSession = true;
        } catch {}
        result.checks.proverAcceptsNestedSession = acceptedNestedSession;

        // ...but unknown keys nested inside `session` must be rejected too.
        let rejectedNestedProver = false;
        try {
            new Prover({
                ...proverConfig(),
                session: { max_num_streams: 4096, maxNumStreams: 1 },
            });
        } catch {
            rejectedNestedProver = true;
        }
        result.checks.proverRejectsUnknownNested = rejectedNestedProver;

        let rejectedNestedVerifier = false;
        try {
            new Verifier({
                ...verifierConfig(),
                session: { max_num_streams: 4096, maxNumStreams: 1 },
            });
        } catch {
            rejectedNestedVerifier = true;
        }
        result.checks.verifierRejectsUnknownNested = rejectedNestedVerifier;

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
