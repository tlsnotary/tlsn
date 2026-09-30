// Type-level contract test for the packaged wasm API.
//
// This file is only compiled by tsc (never executed). It imports the generated
// `pkg/tlsn_wasm.d.ts` exactly like a downstream TS consumer would, so a
// tsify/wasm-bindgen regression that changes the published type surface —
// e.g. a `constructor(config: ProverConfig)` turning into `any` — fails here.
//
// The `@ts-expect-error` cases are the important part: if the type ever
// loosens to `any`, the directive becomes unused and tsc fails with
// "Unused '@ts-expect-error' directive".

import __wbg_init, {
    Prover,
    Verifier,
    compute_reveal,
    initialize,
    type ProverConfig,
    type VerifierConfig,
    type LoggingConfig,
} from "../../pkg/tlsn_wasm.js";

const proverConfig: ProverConfig = {
    server_name: "example.com",
    mode: "Mpc",
    max_sent_data: 1 << 14,
    max_sent_records: undefined,
    max_recv_data_online: undefined,
    max_recv_data: 1 << 14,
    max_recv_records_online: undefined,
    defer_decryption_from_start: undefined,
    network: "Bandwidth",
    client_auth: undefined,
    root_certs: undefined,
};

const verifierConfig: VerifierConfig = {
    max_sent_data: 1 << 14,
    max_recv_data: 1 << 14,
    max_sent_records: undefined,
    max_recv_records_online: undefined,
    root_certs: undefined,
};

const loggingConfig: LoggingConfig = {
    level: "Info",
    crate_filters: undefined,
    span_events: undefined,
};

// Valid usages must compile and keep their published types.
const prover: Prover = new Prover(proverConfig);
const verifier: Verifier = new Verifier(verifierConfig);
const init: Promise<void> = initialize(loggingConfig, 1);
const revealed = compute_reveal(new Uint8Array(), new Uint8Array(), []);
const moduleInit: Promise<unknown> = __wbg_init();

// @ts-expect-error unknown key must be rejected by excess-property checking
new Prover({ ...proverConfig, unknownOption: 4096 });

// @ts-expect-error missing required fields must be rejected
new Prover({ server_name: "example.com" });

// @ts-expect-error wrong value type must be rejected
new Verifier({ ...verifierConfig, max_sent_data: "not-a-number" });

// Keep "unused variable" noise down without changing the point of the file.
void prover;
void verifier;
void init;
void revealed;
void moduleInit;
