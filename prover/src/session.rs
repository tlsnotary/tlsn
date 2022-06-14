use tlsn_core::session::CommonSessionConfig;

pub struct SessionConfig {
    server_name: String,
    common: CommonSessionConfig,
}
