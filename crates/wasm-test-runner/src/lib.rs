use std::fmt::Display;

pub mod chrome_driver;
pub mod server_fixture;
pub mod tlsn_fixture;
pub mod wasm_server;
pub mod ws;

pub static DEFAULT_SERVER_IP: &str = "127.0.0.1";
pub static DEFAULT_WASM_PORT: u16 = 8013;
pub static DEFAULT_WS_PORT: u16 = 8080;
pub static DEFAULT_SERVER_PORT: u16 = 8083;
pub static DEFAULT_VERIFIER_PORT: u16 = 8010;
pub static DEFAULT_NOTARY_PORT: u16 = 8011;
pub static DEFAULT_PROVER_PORT: u16 = 8012;

#[derive(Debug, serde::Deserialize)]
pub struct TestResult {
    pub name: String,
    pub passed: bool,
    pub error: Option<String>,
}

impl Display for TestResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.passed {
            write!(f, "{}: passed", self.name)?;
        } else {
            write!(f, "{}: failed", self.name)?;
            if let Some(error) = &self.error {
                write!(f, "\ncaused by: {}", error)?;
            }
        }

        Ok(())
    }
}
