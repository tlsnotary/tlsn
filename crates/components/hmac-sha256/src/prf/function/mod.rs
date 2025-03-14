pub(crate) mod config;
use config::PrfConfig;

mod state;
pub(crate) use state::State;

#[derive(Debug)]
pub(crate) struct Prf {
    pub(crate) state: State,
    pub(crate) config: PrfConfig,
}

impl Prf {
    const MS_LABEL: &[u8] = b"master secret";
    const KEY_LABEL: &[u8] = b"key expansion";
    const CF_LABEL: &[u8] = b"client finished";
    const SF_LABEL: &[u8] = b"server finished";

    pub(crate) fn new(config: PrfConfig) -> Self {
        Self {
            state: State::Initialized,
            config,
        }
    }
}
