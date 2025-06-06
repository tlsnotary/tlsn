use std::{future::Future, pin::Pin};

use crate::IoProvider;

pub const DEFAULT_TEST_TIMEOUT: u64 = 300;

pub type Fn = for<'a> fn(&'a IoProvider) -> Pin<Box<dyn Future<Output = ()> + 'a>>;

pub(crate) fn get_test(name: &str) -> Option<&'static Test> {
    inventory::iter::<Test>
        .into_iter()
        .find(|test| test.name == name)
}

pub(crate) fn collect_tests() -> Vec<String> {
    inventory::iter::<Test>
        .into_iter()
        .map(|test| test.name.to_string())
        .collect()
}

pub struct Test {
    pub name: &'static str,
    pub prover: Fn,
    pub verifier: Fn,
}

inventory::collect!(Test);

#[macro_export]
macro_rules! test {
    ($name:literal, $prover:ident, $verifier:ident) => {
        inventory::submit!($crate::test::Test {
            name: $name,
            prover: move |io| Box::pin($prover(io)) as _,
            verifier: move |io| Box::pin($verifier(io)) as _,
        });
    };
}
