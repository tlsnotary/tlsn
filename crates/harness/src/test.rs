use std::{future::Future, pin::Pin};

use cfg_if::cfg_if;
use serde::{Deserialize, Serialize};

use crate::{ProverProvider, VerifierProvider};

pub const DEFAULT_TEST_TIMEOUT: u64 = 300;

cfg_if! {
    if #[cfg(target_arch = "wasm32")] {
        pub type ProverTest =
            for<'a> fn(&'a mut ProverProvider) -> Pin<Box<dyn Future<Output = ()> + 'a>>;
        pub type VerifierTest =
            for<'a> fn(&'a mut VerifierProvider) -> Pin<Box<dyn Future<Output = ()> + 'a>>;
    } else {
        pub type ProverTest =
            for<'a> fn(&'a mut ProverProvider) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
        pub type VerifierTest =
            for<'a> fn(&'a mut VerifierProvider) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
    }
}

pub(crate) fn get_test(name: &str) -> Option<&'static Test> {
    inventory::iter::<Test>
        .into_iter()
        .find(|test| test.name == name)
}

pub fn collect_tests(name: Option<&str>) -> Vec<String> {
    inventory::iter::<Test>
        .into_iter()
        .filter_map(|test| {
            if let Some(name) = name {
                if test.name == name {
                    Some(test.name.to_string())
                } else {
                    None
                }
            } else {
                Some(test.name.to_string())
            }
        })
        .collect()
}

pub struct Test {
    pub name: &'static str,
    pub prover: ProverTest,
    pub verifier: VerifierTest,
}

inventory::collect!(Test);

macro_rules! test {
    ($name:literal, $prover:ident, $verifier:ident) => {
        inventory::submit!(crate::test::Test {
            name: $name,
            prover: move |p| Box::pin($prover(p)) as _,
            verifier: move |v| Box::pin($verifier(v)) as _,
        });
    };
}
pub(crate) use test;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestConfig {
    pub name: String,
    pub timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserTestConfig {
    pub test: TestConfig,
    pub proxy_addr: (String, u16),
    pub server_addr: (String, u16),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestOutput {
    pub passed: bool,
    pub time: u64,
    pub timed_out: bool,
}
