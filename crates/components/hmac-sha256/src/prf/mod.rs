use crate::{PrfError, PrfOutput, SessionKeys};
use mpz_circuits::{Circuit, CircuitBuilder};
use mpz_vm_core::{
    memory::{
        binary::{Binary, U32, U8},
        Array, FromRaw, StaticSize, ToRaw, Vector,
    },
    prelude::*,
    Call, Vm,
};
use std::{fmt::Debug, sync::Arc};
use tracing::instrument;

mod state;
use state::State;

mod function;
use function::PrfFunction;

/// MPC PRF for computing TLS HMAC-SHA256 PRF.
#[derive(Debug)]
pub struct MpcPrf {
    state: State,
    circuits: Option<Circuits>,
}

impl Default for MpcPrf {
    fn default() -> Self {
        Self::new()
    }
}

impl MpcPrf {
    /// Creates a new instance of the PRF.
    pub fn new() -> MpcPrf {
        Self {
            state: State::Initialized,
            circuits: None,
        }
    }

    /// Allocates resources for the PRF.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    /// * `pms` - The pre-master secret.
    #[instrument(level = "debug", skip_all, err)]
    pub fn alloc(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        pms: Array<U8, 32>,
    ) -> Result<PrfOutput, PrfError> {
        let State::Initialized = self.state.take() else {
            return Err(PrfError::state("PRF not in initialized state"));
        };

        let circuits = Circuits::alloc(vm, pms.into())?;

        let keys = circuits.get_session_keys(vm)?;
        let cf_vd = circuits.get_client_finished_vd(vm)?;
        let sf_vd = circuits.get_server_finished_vd(vm)?;

        let prf_output = PrfOutput { keys, cf_vd, sf_vd };

        self.circuits = Some(circuits);
        self.state = State::SessionKeys {
            client_random: None,
        };

        Ok(prf_output)
    }

    /// Sets the client random.
    ///
    /// # Arguments
    ///
    /// * `random` - The client random.
    #[instrument(level = "debug", skip_all, err)]
    pub fn set_client_random(&mut self, random: [u8; 32]) -> Result<(), PrfError> {
        let State::SessionKeys { client_random } = &mut self.state else {
            return Err(PrfError::state("PRF not set up"));
        };

        *client_random = Some(random);
        Ok(())
    }

    /// Sets the server random.
    ///
    /// # Arguments
    ///
    /// * `random` - The server random.
    #[instrument(level = "debug", skip_all, err)]
    pub fn set_server_random(&mut self, random: [u8; 32]) -> Result<(), PrfError> {
        let State::SessionKeys { client_random } = self.state.take() else {
            return Err(PrfError::state("PRF not set up"));
        };

        let Some(ref mut circuits) = self.circuits else {
            return Err(PrfError::state("Circuits should have been set for PRF"));
        };

        let client_random = client_random.expect("Client random should have been set by now");
        let server_random = random;

        let mut seed_ms = client_random.to_vec();
        seed_ms.extend_from_slice(&server_random);
        circuits.master_secret.set_start_seed(seed_ms);

        let mut seed_ke = server_random.to_vec();
        seed_ke.extend_from_slice(&client_random);
        circuits.key_expansion.set_start_seed(seed_ke);

        self.state = State::ClientFinished;
        Ok(())
    }

    /// Sets the client finished handshake hash.
    ///
    /// # Arguments
    ///
    /// * `handshake_hash` - The handshake transcript hash.
    #[instrument(level = "debug", skip_all, err)]
    pub fn set_cf_hash(&mut self, handshake_hash: [u8; 32]) -> Result<(), PrfError> {
        let State::ClientFinished { .. } = self.state.take() else {
            return Err(PrfError::state("PRF not in client finished state"));
        };

        let Some(ref mut circuits) = self.circuits else {
            return Err(PrfError::state("Circuits should have been set for PRF"));
        };

        let seed_cf = handshake_hash.to_vec();
        circuits.client_finished.set_start_seed(seed_cf);

        self.state = State::ServerFinished;
        Ok(())
    }

    /// Sets the server finished handshake hash.
    ///
    /// # Arguments
    ///
    /// * `handshake_hash` - The handshake transcript hash.
    #[instrument(level = "debug", skip_all, err)]
    pub fn set_sf_hash(&mut self, handshake_hash: [u8; 32]) -> Result<(), PrfError> {
        let State::ServerFinished = self.state.take() else {
            return Err(PrfError::state("PRF not in server finished state"));
        };

        let Some(ref mut circuits) = self.circuits else {
            return Err(PrfError::state("Circuits should have been set for PRF"));
        };

        let seed_sf = handshake_hash.to_vec();
        circuits.server_finished.set_start_seed(seed_sf);

        self.state = State::Complete;
        Ok(())
    }
}

#[derive(Debug)]
struct Circuits {
    pub(crate) master_secret: PrfFunction,
    pub(crate) key_expansion: PrfFunction,
    pub(crate) client_finished: PrfFunction,
    pub(crate) server_finished: PrfFunction,
}

impl Circuits {
    fn alloc(vm: &mut dyn Vm<Binary>, pms: Vector<U8>) -> Result<Self, PrfError> {
        let master_secret = PrfFunction::alloc_master_secret(vm, pms)?;
        let ms = master_secret.output();

        let ms = merge_outputs(vm, ms, 48)?;

        let circuits = Self {
            master_secret,
            key_expansion: PrfFunction::alloc_key_expansion(vm, ms)?,
            client_finished: PrfFunction::alloc_client_finished(vm, ms)?,
            server_finished: PrfFunction::alloc_server_finished(vm, ms)?,
        };
        Ok(circuits)
    }

    fn get_session_keys(&self, vm: &mut dyn Vm<Binary>) -> Result<SessionKeys, PrfError> {
        let key_expansion = &self.key_expansion;
        let keys = key_expansion.output();

        let mut keys = merge_outputs(vm, keys, 40)?;

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

    fn get_client_finished_vd(&self, vm: &mut dyn Vm<Binary>) -> Result<Array<U8, 12>, PrfError> {
        let client_finished = &self.client_finished;
        let cf_vd = client_finished.output();

        let cf_vd = merge_outputs(vm, cf_vd, 12)?;
        let cf_vd = <Array<U8, 12> as FromRaw<Binary>>::from_raw(cf_vd.to_raw());

        Ok(cf_vd)
    }

    fn get_server_finished_vd(&self, vm: &mut dyn Vm<Binary>) -> Result<Array<U8, 12>, PrfError> {
        let server_finished = &self.server_finished;
        let sf_vd = server_finished.output();

        let sf_vd = merge_outputs(vm, sf_vd, 12)?;
        let sf_vd = <Array<U8, 12> as FromRaw<Binary>>::from_raw(sf_vd.to_raw());

        Ok(sf_vd)
    }
}

fn merge_outputs(
    vm: &mut dyn Vm<Binary>,
    inputs: Vec<Array<U32, 8>>,
    output_bytes: usize,
) -> Result<Vector<U8>, PrfError> {
    assert!(output_bytes <= 32 * inputs.len());

    let bits = Array::<U32, 8>::SIZE * inputs.len();
    let id_circ = identity_circuit(bits);

    let mut builder = Call::builder(id_circ);
    for &input in inputs.iter() {
        builder = builder.arg(input);
    }
    let call = builder.build().map_err(PrfError::vm)?;

    let mut output: Vector<U8> = vm.call(call).map_err(PrfError::vm)?;
    output.truncate(output_bytes);
    Ok(output)
}

fn identity_circuit(size: usize) -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new();
    let inputs = (0..size).map(|_| builder.add_input()).collect::<Vec<_>>();

    for input in inputs.into_iter() {
        let output = builder.add_id_gate(input);
        builder.add_output(output);
    }

    Arc::new(builder.build().expect("identity circuit is valid"))
}
