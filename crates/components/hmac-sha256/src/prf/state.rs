use crate::{
    prf::{function::Prf, merge_outputs},
    PrfError, PrfOutput, SessionKeys,
};
use mpz_vm_core::{
    memory::{
        binary::{Binary, U32, U8},
        Array, FromRaw, ToRaw,
    },
    Vm,
};

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

    pub(crate) fn prf_output(&self, vm: &mut dyn Vm<Binary>) -> Result<PrfOutput, PrfError> {
        let State::SessionKeys {
            key_expansion,
            client_finished,
            server_finished,
            ..
        } = self
        else {
            return Err(PrfError::state(
                "Prf output can only be computed while in \"SessionKeys\" state",
            ));
        };

        let keys = get_session_keys(key_expansion.output(), vm)?;
        let cf_vd = get_client_finished_vd(client_finished.output(), vm)?;
        let sf_vd = get_server_finished_vd(server_finished.output(), vm)?;

        let output = PrfOutput { keys, cf_vd, sf_vd };

        Ok(output)
    }
}

fn get_session_keys(
    output: Vec<Array<U32, 8>>,
    vm: &mut dyn Vm<Binary>,
) -> Result<SessionKeys, PrfError> {
    let mut keys = merge_outputs(vm, output, 40)?;

    let server_iv = <Array<U8, 4> as FromRaw<Binary>>::from_raw(keys.split_off(36).to_raw());
    let client_iv = <Array<U8, 4> as FromRaw<Binary>>::from_raw(keys.split_off(32).to_raw());
    let server_write_key =
        <Array<U8, 16> as FromRaw<Binary>>::from_raw(keys.split_off(16).to_raw());
    let client_write_key = <Array<U8, 16> as FromRaw<Binary>>::from_raw(keys.to_raw());

    let session_keys = SessionKeys {
        client_write_key,
        server_write_key,
        client_iv,
        server_iv,
    };

    Ok(session_keys)
}

fn get_client_finished_vd(
    output: Vec<Array<U32, 8>>,
    vm: &mut dyn Vm<Binary>,
) -> Result<Array<U8, 12>, PrfError> {
    let cf_vd = merge_outputs(vm, output, 12)?;
    let cf_vd = <Array<U8, 12> as FromRaw<Binary>>::from_raw(cf_vd.to_raw());

    Ok(cf_vd)
}

fn get_server_finished_vd(
    output: Vec<Array<U32, 8>>,
    vm: &mut dyn Vm<Binary>,
) -> Result<Array<U8, 12>, PrfError> {
    let sf_vd = merge_outputs(vm, output, 12)?;
    let sf_vd = <Array<U8, 12> as FromRaw<Binary>>::from_raw(sf_vd.to_raw());

    Ok(sf_vd)
}
