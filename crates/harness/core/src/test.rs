use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TestStatus {
    Passed,
    Failed { reason: Option<String> },
    TimedOut,
}

impl TestStatus {
    /// Returns `true` if the test passed.
    pub fn is_passed(&self) -> bool {
        matches!(self, TestStatus::Passed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestOutput {
    pub status: TestStatus,
}
