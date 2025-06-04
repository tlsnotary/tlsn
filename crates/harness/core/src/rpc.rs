use enum_try_as_inner::EnumTryAsInner;
use serde::{Deserialize, Serialize};

use crate::{
    Role,
    bench::{Bench, BenchOutput},
    test::TestOutput,
};

pub type Result<T, E = RpcError> = std::result::Result<T, E>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Cmd {
    GetTests,
    Test(TestCmd),
    Bench(BenchCmd),
}

#[derive(Debug, Clone, EnumTryAsInner, Serialize, Deserialize)]
pub enum CmdOutput {
    Empty,
    GetTests(Vec<String>),
    Test(TestOutput),
    Bench(BenchOutput),
    Fail { reason: Option<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCmd {
    pub name: String,
    pub role: Role,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchCmd {
    pub config: Bench,
    pub role: Role,
}

#[derive(Debug, thiserror::Error, Serialize, Deserialize)]
#[error("rpc error: {reason}")]
pub struct RpcError {
    reason: String,
}

impl RpcError {
    pub fn new(reason: impl ToString) -> Self {
        Self {
            reason: reason.to_string(),
        }
    }

    /// The reason for the error.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl From<CmdOutputError> for RpcError {
    fn from(value: CmdOutputError) -> Self {
        RpcError {
            reason: format!(
                "unexpected command output: expected {}, got {}",
                value.expected(),
                value.actual()
            ),
        }
    }
}
