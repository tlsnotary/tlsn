#[derive(Debug)]
pub(crate) enum State {
    Initialized,
    SessionKeys { client_random: Option<[u8; 32]> },
    ClientFinished,
    ServerFinished,
    Complete,
    Error,
}

impl State {
    pub(crate) fn take(&mut self) -> State {
        std::mem::replace(self, State::Error)
    }
}
