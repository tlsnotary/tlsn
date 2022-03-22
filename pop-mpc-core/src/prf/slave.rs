use super::H;

pub struct Initialized;
pub struct Ms1;

pub trait State {}
impl State for Initialized {}
impl State for Ms1 {}

pub struct PrfSlave<S>
where
    S: State,
{
    /// State of 2PC PRF Protocol
    state: S,
}

impl PrfSlave<Initialized> {
    pub fn new() -> Self {
        Self { state: Initialized }
    }

    pub fn next(self) -> ((), PrfSlave<Ms1>) {
        todo!()
    }
}
