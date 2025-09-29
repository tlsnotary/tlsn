use crate::{prf::Prf, FError, PrfOutput, SessionKeys};
use mpz_vm_core::memory::{binary::U8, Array};

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(crate) enum State {
    Initialized,
    SessionKeys {
        client_random: Option<[u8; 32]>,
        master_secret: Prf,
        key_expansion: Prf,
        client_finished: Prf,
        server_finished: Prf,
    },
    ClientFinished {
        client_finished: Prf,
        server_finished: Prf,
    },
    ServerFinished {
        server_finished: Prf,
    },
    Complete,
    Error,
}

impl State {
    pub(crate) fn take(&mut self) -> State {
        std::mem::replace(self, State::Error)
    }

    pub(crate) fn prf_output(&self) -> Result<PrfOutput, FError> {
        let State::SessionKeys {
            key_expansion,
            client_finished,
            server_finished,
            ..
        } = self
        else {
            return Err(FError::state(
                "Prf output can only be computed while in \"SessionKeys\" state",
            ));
        };

        let keys = get_session_keys(
            key_expansion
                .output()
                .try_into()
                .expect("session keys are 40 bytes"),
        );

        let output = PrfOutput {
            keys,
            cf_vd: client_finished
                .output()
                .try_into()
                .expect("client finished is 12 bytes"),
            sf_vd: server_finished
                .output()
                .try_into()
                .expect("server finished is 12 bytes"),
        };

        Ok(output)
    }
}

fn get_session_keys(keys: Array<U8, 40>) -> SessionKeys {
    let client_write_key = keys.get::<16>(0).expect("within bounds");
    let server_write_key = keys.get::<16>(16).expect("within bounds");
    let client_iv = keys.get::<4>(32).expect("within bounds");
    let server_iv = keys.get::<4>(36).expect("within bounds");

    SessionKeys {
        client_write_key,
        server_write_key,
        client_iv,
        server_iv,
    }
}
