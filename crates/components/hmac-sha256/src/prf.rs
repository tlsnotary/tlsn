use std::{
    fmt::Debug,
    sync::{Arc, OnceLock},
};

use hmac_sha256_circuits::{build_session_keys, build_verify_data};
use mpz_circuits::Circuit;
use mpz_common::cpu::CpuBackend;
use mpz_vm_core::{
    memory::{
        binary::{Binary, U32, U8},
        Array,
    },
    prelude::*,
    Call, Vm,
};
use tracing::instrument;

use crate::{PrfConfig, PrfError, PrfOutput, Role, SessionKeys, CF_LABEL, SF_LABEL};

pub(crate) struct Circuits {
    session_keys: Arc<Circuit>,
    client_vd: Arc<Circuit>,
    server_vd: Arc<Circuit>,
}

impl Circuits {
    pub(crate) async fn get() -> &'static Self {
        static CIRCUITS: OnceLock<Circuits> = OnceLock::new();
        if let Some(circuits) = CIRCUITS.get() {
            return circuits;
        }

        let (session_keys, client_vd, server_vd) = futures::join!(
            CpuBackend::blocking(build_session_keys),
            CpuBackend::blocking(|| build_verify_data(CF_LABEL)),
            CpuBackend::blocking(|| build_verify_data(SF_LABEL)),
        );

        _ = CIRCUITS.set(Circuits {
            session_keys,
            client_vd,
            server_vd,
        });

        CIRCUITS.get().unwrap()
    }
}

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
    fn take(&mut self) -> State {
        std::mem::replace(self, State::Error)
    }
}

/// MPC PRF for computing TLS HMAC-SHA256 PRF.
pub struct MpcPrf {
    config: PrfConfig,
    state: State,
}

impl Debug for MpcPrf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcPrf")
            .field("config", &self.config)
            .field("state", &self.state)
            .finish()
    }
}

impl MpcPrf {
    /// Creates a new instance of the PRF.
    pub fn new(config: PrfConfig) -> MpcPrf {
        MpcPrf {
            config,
            state: State::Initialized,
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

        let circuits = futures::executor::block_on(Circuits::get());

        let client_random = vm.alloc().map_err(PrfError::vm)?;
        let server_random = vm.alloc().map_err(PrfError::vm)?;

        // The client random is kept private so that the handshake transcript
        // hashes do not leak information about the server's identity.
        match self.config.role {
            Role::Leader => vm.mark_private(client_random),
            Role::Follower => vm.mark_blind(client_random),
        }
        .map_err(PrfError::vm)?;

        vm.mark_public(server_random).map_err(PrfError::vm)?;

        #[allow(clippy::type_complexity)]
        let (
            client_write_key,
            server_write_key,
            client_iv,
            server_iv,
            ms_outer_hash_state,
            ms_inner_hash_state,
        ): (
            Array<U8, 16>,
            Array<U8, 16>,
            Array<U8, 4>,
            Array<U8, 4>,
            Array<U32, 8>,
            Array<U32, 8>,
        ) = vm
            .call(
                Call::builder(circuits.session_keys.clone())
                    .arg(pms)
                    .arg(client_random)
                    .arg(server_random)
                    .build()
                    .map_err(PrfError::vm)?,
            )
            .map_err(PrfError::vm)?;

        let keys = SessionKeys {
            client_write_key,
            server_write_key,
            client_iv,
            server_iv,
        };

        let cf_hash = vm.alloc().map_err(PrfError::vm)?;
        vm.mark_public(cf_hash).map_err(PrfError::vm)?;

        let cf_vd = vm
            .call(
                Call::builder(circuits.client_vd.clone())
                    .arg(ms_outer_hash_state)
                    .arg(ms_inner_hash_state)
                    .arg(cf_hash)
                    .build()
                    .map_err(PrfError::vm)?,
            )
            .map_err(PrfError::vm)?;

        let sf_hash = vm.alloc().map_err(PrfError::vm)?;
        vm.mark_public(sf_hash).map_err(PrfError::vm)?;

        let sf_vd = vm
            .call(
                Call::builder(circuits.server_vd.clone())
                    .arg(ms_outer_hash_state)
                    .arg(ms_inner_hash_state)
                    .arg(sf_hash)
                    .build()
                    .map_err(PrfError::vm)?,
            )
            .map_err(PrfError::vm)?;

        self.state = State::SessionKeys {
            client_random,
            server_random,
            cf_hash,
            sf_hash,
        };

        Ok(PrfOutput { keys, cf_vd, sf_vd })
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
        let State::SessionKeys { client_random, .. } = &self.state else {
            return Err(PrfError::state("PRF not set up"));
        };

        if self.config.role == Role::Leader {
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
        } = self.state.take()
        else {
            return Err(PrfError::state("PRF not set up"));
        };

        vm.assign(server_random, random).map_err(PrfError::vm)?;
        vm.commit(server_random).map_err(PrfError::vm)?;

        self.state = State::ClientFinished { cf_hash, sf_hash };

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
        let State::ClientFinished { cf_hash, sf_hash } = self.state.take() else {
            return Err(PrfError::state("PRF not in client finished state"));
        };

        vm.assign(cf_hash, handshake_hash).map_err(PrfError::vm)?;
        vm.commit(cf_hash).map_err(PrfError::vm)?;

        self.state = State::ServerFinished { sf_hash };

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
        let State::ServerFinished { sf_hash } = self.state.take() else {
            return Err(PrfError::state("PRF not in server finished state"));
        };

        vm.assign(sf_hash, handshake_hash).map_err(PrfError::vm)?;
        vm.commit(sf_hash).map_err(PrfError::vm)?;

        self.state = State::Complete;

        Ok(())
    }
}
