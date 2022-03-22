use super::H;

pub struct Initialized;
pub struct Ms1;

pub trait State {}
impl State for Initialized {}
impl State for Ms1 {}

pub struct PrfMaster<S>
where
    S: State,
{
    /// State of 2PC PRF Protocol
    state: S,
}

impl PrfMaster<Initialized> {
    pub fn new(seed: &str) -> Self {
        Self { state: Initialized }
    }

    pub fn next(self) -> ((), PrfMaster<Ms1>) {
        todo!()
    }
}
