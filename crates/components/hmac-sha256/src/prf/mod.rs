use crate::{PrfError, PrfOutput};
use mpz_vm_core::{
    memory::{
        binary::{Binary, U8},
        Array,
    },
    prelude::*,
    Vm,
};
use std::fmt::Debug;
use tracing::instrument;

mod function;
pub use function::config::{PrfConfig, PrfConfigBuilder, Role};
use function::{Prf, State};

/// MPC PRF for computing TLS HMAC-SHA256 PRF.
pub struct MpcPrf {
    prf: Prf,
}

impl Debug for MpcPrf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcPrf").field("prf", &self.prf).finish()
    }
}

impl MpcPrf {
    /// Creates a new instance of the PRF.
    pub fn new(config: PrfConfig) -> MpcPrf {
        MpcPrf {
            prf: Prf::new(config),
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
        let State::Initialized = self.prf.state.take() else {
            return Err(PrfError::state("PRF not in initialized state"));
        };
        todo!()
    }

    /// Sets the client random.
    ///
    /// Only the leader can provide the client random.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    /// * `client_random` - The client random.
    #[instrument(level = "debug", skip_all, err)]
    pub fn set_client_random(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        random: Option<[u8; 32]>,
    ) -> Result<(), PrfError> {
        let State::SessionKeys { client_random, .. } = &self.prf.state else {
            return Err(PrfError::state("PRF not set up"));
        };

        if self.prf.config.role == Role::Leader {
            let Some(random) = random else {
                return Err(PrfError::role("leader must provide client random"));
            };

            vm.assign(*client_random, random).map_err(PrfError::vm)?;
        } else if random.is_some() {
            return Err(PrfError::role("only leader can set client random"));
        }

        vm.commit(*client_random).map_err(PrfError::vm)?;

        Ok(())
    }

    /// Sets the server random.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    /// * `server_random` - The server random.
    #[instrument(level = "debug", skip_all, err)]
    pub fn set_server_random(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        random: [u8; 32],
    ) -> Result<(), PrfError> {
        let State::SessionKeys {
            server_random,
            cf_hash,
            sf_hash,
            ..
        } = self.prf.state.take()
        else {
            return Err(PrfError::state("PRF not set up"));
        };

        vm.assign(server_random, random).map_err(PrfError::vm)?;
        vm.commit(server_random).map_err(PrfError::vm)?;

        self.prf.state = State::ClientFinished { cf_hash, sf_hash };

        Ok(())
    }

    /// Sets the client finished handshake hash.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    /// * `handshake_hash` - The handshake transcript hash.
    #[instrument(level = "debug", skip_all, err)]
    pub fn set_cf_hash(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        handshake_hash: [u8; 32],
    ) -> Result<(), PrfError> {
        let State::ClientFinished { cf_hash, sf_hash } = self.prf.state.take() else {
            return Err(PrfError::state("PRF not in client finished state"));
        };

        vm.assign(cf_hash, handshake_hash).map_err(PrfError::vm)?;
        vm.commit(cf_hash).map_err(PrfError::vm)?;

        self.prf.state = State::ServerFinished { sf_hash };

        Ok(())
    }

    /// Sets the server finished handshake hash.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    /// * `handshake_hash` - The handshake transcript hash.
    #[instrument(level = "debug", skip_all, err)]
    pub fn set_sf_hash(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        handshake_hash: [u8; 32],
    ) -> Result<(), PrfError> {
        let State::ServerFinished { sf_hash } = self.prf.state.take() else {
            return Err(PrfError::state("PRF not in server finished state"));
        };

        vm.assign(sf_hash, handshake_hash).map_err(PrfError::vm)?;
        vm.commit(sf_hash).map_err(PrfError::vm)?;

        self.prf.state = State::Complete;

        Ok(())
    }
}
