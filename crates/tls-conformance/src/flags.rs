//! The BoGo command-line flag vocabulary and prefix classification.
//!
//! The [`BOOL_FLAGS`] and [`VALUE_FLAGS`] tables are sourced from BoringSSL's
//! `ssl/test/test_config.cc` and are used only to classify argv (does this flag
//! take a following value?). [`UNSUPPORTED_FLAGS`] is the semantic subset that
//! maps to a feature TLSNotary's MPC-TLS client cannot do.

/// Result of stripping a raw argv token's `-on-*` connection-scope prefix.
#[derive(Debug, PartialEq, Eq)]
pub enum FlagToken<'a> {
    /// Process this (prefix-stripped) inner flag.
    Inner(&'a str),
    /// Scenario targets a connection phase we don't support; skip the test.
    Skip,
}

/// Classifies a raw argv token's `-on-{shim,initial,resume,retry,handshaker}-`
/// prefix. These scope a flag to a particular connection; we only ever make one
/// connection, so `resume`/`retry`/`handshaker` variants imply unsupported
/// features, while `shim`/`initial` simply apply to our single connection.
pub fn classify_prefix(raw: &str) -> FlagToken<'_> {
    for prefix in ["-on-resume", "-on-retry", "-on-handshaker"] {
        if let Some(rest) = raw.strip_prefix(prefix)
            && rest.starts_with('-')
        {
            return FlagToken::Skip;
        }
    }
    for prefix in ["-on-shim", "-on-initial"] {
        if let Some(rest) = raw.strip_prefix(prefix)
            && rest.starts_with('-')
        {
            return FlagToken::Inner(rest);
        }
    }
    FlagToken::Inner(raw)
}

/// Flags that map to a feature TLSNotary's MPC-TLS client cannot do. Seeing any
/// of these skips the test (so the runner ignores it rather than counting a
/// confusing failure). Every entry must also appear in [`BOOL_FLAGS`] or
/// [`VALUE_FLAGS`] (enforced by a unit test).
pub const UNSUPPORTED_FLAGS: &[&str] = &[
    "-server",                 // we are a client only
    "-dtls",                   // DTLS
    "-quic",                   // QUIC
    "-no-tls12",               // disables our only supported version
    "-enable-early-data",      // TLS 1.3 0-RTT
    "-key-update",             // TLS 1.3 key update
    "-key-update-before-read", // TLS 1.3 key update
    "-renegotiate-once",       // renegotiation
    "-renegotiate-freely",     // renegotiation
    "-renegotiate-ignore",     // renegotiation
    "-renegotiate-explicit",   // renegotiation
    "-enable-channel-id",      // Channel ID
    "-fallback-scsv",          // downgrade-protection SCSV
    "-psk",                    // pre-shared keys
    "-psk-identity",           // pre-shared keys
];

/// Boolean BoGo flags (take no value). Used only to classify argv.
pub const BOOL_FLAGS: &[&str] = &[
    "-ipv6",
    "-server",
    "-dtls",
    "-quic",
    "-fuzzer-mode",
    "-fallback-scsv",
    "-enable-ech-grease",
    "-expect-ech-accept",
    "-expect-no-ech-name-override",
    "-expect-no-ech-retry-configs",
    "-require-any-client-certificate",
    "-advertise-empty-npn",
    "-expect-no-next-proto",
    "-false-start",
    "-select-empty-next-proto",
    "-async",
    "-write-different-record-sizes",
    "-cbc-record-splitting",
    "-partial-write",
    "-no-tls13",
    "-no-tls12",
    "-no-tls11",
    "-no-tls1",
    "-no-ticket",
    "-no-legacy-server-connect",
    "-enable-channel-id",
    "-shim-writes-first",
    "-decline-alpn",
    "-reject-alpn",
    "-select-empty-alpn",
    "-defer-alps",
    "-expect-session-miss",
    "-expect-extended-master-secret",
    "-enable-ocsp-stapling",
    "-enable-signed-cert-timestamps",
    "-implicit-handshake",
    "-use-early-callback",
    "-fail-early-callback",
    "-fail-early-callback-ech-rewind",
    "-install-ddos-callback",
    "-fail-ddos-callback",
    "-fail-cert-callback",
    "-handshake-never-done",
    "-use-export-context",
    "-tls-unique",
    "-expect-ticket-renewal",
    "-expect-no-session",
    "-expect-ticket-supports-early-data",
    "-expect-accept-early-data",
    "-expect-reject-early-data",
    "-expect-no-offer-early-data",
    "-expect-no-server-name",
    "-use-ticket-callback",
    "-use-ticket-aead-callback",
    "-renew-ticket",
    "-skip-ticket",
    "-enable-early-data",
    "-check-close-notify",
    "-shim-shuts-down",
    "-verify-fail",
    "-verify-peer",
    "-expect-verify-result",
    "-renegotiate-once",
    "-renegotiate-freely",
    "-renegotiate-ignore",
    "-renegotiate-explicit",
    "-forbid-renegotiation-after-handshake",
    "-use-old-client-cert-callback",
    "-send-alert",
    "-peek-then-read",
    "-enable-grease",
    "-permute-extensions",
    "-use-exporter-between-reads",
    "-expect-no-peer-cert",
    "-retain-only-sha256-client-cert",
    "-expect-sha256-client-cert",
    "-read-with-unfinished-write",
    "-expect-secure-renegotiation",
    "-expect-no-secure-renegotiation",
    "-expect-session-id",
    "-expect-no-session-id",
    "-no-op-extra-handshake",
    "-handshake-twice",
    "-allow-unknown-alpn-protos",
    "-use-custom-verify-callback",
    "-allow-false-start-without-alpn",
    "-handoff",
    "-handshake-hints",
    "-allow-hint-mismatch",
    "-use-ocsp-callback",
    "-set-ocsp-in-callback",
    "-decline-ocsp-callback",
    "-fail-ocsp-callback",
    "-install-cert-compression-algs",
    "-reverify-on-resume",
    "-ignore-rsa-key-usage",
    "-expect-key-usage-invalid",
    "-is-handshaker-supported",
    "-handshaker-resume",
    "-jdk11-workaround",
    "-server-preference",
    "-export-traffic-secrets",
    "-key-update",
    "-key-update-before-read",
    "-expect-hrr",
    "-expect-no-hrr",
    "-wait-for-debugger",
    "-fips-202205",
    "-wpa-202304",
    "-cnsa-202407",
    "-cnsa1-202603",
    "-cnsa2-202603",
    "-expect-peer-match-trust-anchor",
    "-expect-no-peer-match-trust-anchor",
    "-no-key-shares",
    "-must-match-issuer",
    "-wrong-pake-role",
    "-psk-importer-sha256",
    "-psk-importer-sha384",
    "-resumption-across-names-enabled",
    "-expect-resumable-across-names",
    "-expect-not-resumable-across-names",
    "-no-server-name-ack",
    "-expect-server-sent-requested-padding",
    "-server-supports-padding",
    "-new-x509-credential",
    "-new-delegated-credential",
    "-new-spake2plusv1-credential",
    "-new-psk-credential",
    "-new-rpk-credential",
];

/// BoGo flags that take a following value argument. Used only to classify argv.
pub const VALUE_FLAGS: &[&str] = &[
    "-port",
    "-shim-id",
    "-resume-count",
    "-write-settings",
    "-verify-prefs",
    "-expect-peer-verify-pref",
    "-curves",
    "-curves-flags",
    "-key-shares",
    "-server-supported-groups-hint",
    "-trust-cert",
    "-expect-server-name",
    "-ech-server-config",
    "-ech-server-key",
    "-ech-is-retry-config",
    "-expect-ech-name-override",
    "-expect-ech-retry-configs",
    "-ech-config-list",
    "-expect-certificate-types",
    "-advertise-npn",
    "-expect-next-proto",
    "-select-next-proto",
    "-host-name",
    "-advertise-alpn",
    "-expect-alpn",
    "-expect-advertised-alpn",
    "-select-alpn",
    "-application-settings",
    "-expect-peer-application-settings",
    "-alps-use-new-codepoint",
    "-quic-transport-params",
    "-expect-quic-transport-params",
    "-quic-use-legacy-codepoint",
    "-psk",
    "-psk-identity",
    "-srtp-profiles",
    "-expect-signed-cert-timestamps",
    "-min-version",
    "-max-version",
    "-expect-version",
    "-mtu",
    "-export-keying-material",
    "-export-label",
    "-export-context",
    "-cipher",
    "-expect-ocsp-response",
    "-expect-total-renegotiations",
    "-expect-peer-signature-algorithm",
    "-expect-curve-id",
    "-initial-timeout-duration-ms",
    "-use-client-ca-list",
    "-expect-client-ca-list",
    "-max-cert-list",
    "-ticket-key",
    "-expect-cipher-aes",
    "-expect-cipher-no-aes",
    "-expect-cipher",
    "-expect-peer-cert-file",
    "-resumption-delay",
    "-max-send-fragment",
    "-read-size",
    "-expect-ticket-age-skew",
    "-expect-msg-callback",
    "-handshaker-path",
    "-expect-early-data-reason",
    "-quic-early-data-context",
    "-early-write-after-message",
    "-expect-peer-available-trust-anchors",
    "-requested-trust-anchors",
    "-available-trust-anchors",
    "-expect-selected-credential",
    "-cert-file",
    "-key-file",
    "-signing-prefs",
    "-delegated-credential",
    "-ocsp-response",
    "-signed-cert-timestamps",
    "-pake-context",
    "-pake-client-id",
    "-pake-server-id",
    "-pake-password",
    "-psk-importer-key",
    "-psk-importer-identity",
    "-psk-importer-context",
    "-trust-anchor-id",
    "-private-key-delay-ms",
    "-accepted-peer-cert-types",
    "-available-client-cert-types",
    "-expect-peer-certificate-type",
    "-expect-peer-rpk-sha256",
    "-request-server-padding",
    "-repeat-shim-initial-write",
    "-shim-initial-write",
    "-install-one-cert-compression-alg",
];
