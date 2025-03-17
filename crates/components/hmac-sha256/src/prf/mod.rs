use crate::{PrfError, PrfOutput};
use mpz_vm_core::{
    memory::{
        binary::{Binary, U8},
        Array, Vector,
    },
    prelude::*,
    Vm,
};
use std::fmt::Debug;
use tracing::instrument;

mod config;
pub use config::{PrfConfig, PrfConfigBuilder, Role};

mod state;
use state::State;

mod function;
use function::PrfFunction;

/// MPC PRF for computing TLS HMAC-SHA256 PRF.
#[derive(Debug)]
pub struct MpcPrf {
    config: PrfConfig,
    state: State,
    circuits: Option<Circuits>,
}

impl MpcPrf {
    /// Creates a new instance of the PRF.
    pub fn new(config: PrfConfig) -> MpcPrf {
        Self {
            config,
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

        let ms: Array<U8, 40> = vm.alloc().map_err(PrfError::vm)?;

        let prf_output = PrfOutput::alloc(vm)?;
        let circuits = Circuits::alloc(vm, pms.into(), ms.into())?;

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
    pub fn set_client_random(&mut self, random: Option<[u8; 32]>) -> Result<(), PrfError> {
        let State::SessionKeys { client_random } = &mut self.state else {
            return Err(PrfError::state("PRF not set up"));
        };

        *client_random = random;
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
    fn alloc(vm: &mut dyn Vm<Binary>, pms: Vector<U8>, ms: Vector<U8>) -> Result<Self, PrfError> {
        let circuits = Self {
            master_secret: PrfFunction::alloc_master_secret(vm, pms)?,
            key_expansion: PrfFunction::alloc_key_expansion(vm, ms)?,
            client_finished: PrfFunction::alloc_client_finished(vm, ms)?,
            server_finished: PrfFunction::alloc_server_finished(vm, ms)?,
        };
        Ok(circuits)
    }
}
