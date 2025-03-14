use mpz_vm_core::memory::{binary::U8, Array};

#[derive(Debug)]
pub(crate) enum State {
    Initialized,
    SessionKeys {
        client_random: Array<U8, 32>,
        server_random: Array<U8, 32>,
        cf_hash: Array<U8, 32>,
        sf_hash: Array<U8, 32>,
    },
    ClientFinished {
        cf_hash: Array<U8, 32>,
        sf_hash: Array<U8, 32>,
    },
    ServerFinished {
        sf_hash: Array<U8, 32>,
    },
    Complete,
    Error,
}

impl State {
    pub(crate) fn take(&mut self) -> State {
        std::mem::replace(self, State::Error)
    }
}
