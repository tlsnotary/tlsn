use std::{
    fmt::Debug,
    sync::{Arc, OnceLock},
};

use async_trait::async_trait;

use hmac_sha256_circuits::{build_session_keys, build_verify_data};
use mpz_circuits::Circuit;
use mpz_common::cpu::CpuBackend;
use mpz_garble::{config::Visibility, value::ValueRef, Decode, Execute, Load, Memory};
use tracing::instrument;

use crate::{Prf, PrfConfig, PrfError, Role, SessionKeys, CF_LABEL, SF_LABEL};

/// Circuit for computing TLS session keys.
static SESSION_KEYS_CIRC: OnceLock<Arc<Circuit>> = OnceLock::new();
/// Circuit for computing TLS client verify data.
static CLIENT_VD_CIRC: OnceLock<Arc<Circuit>> = OnceLock::new();
/// Circuit for computing TLS server verify data.
static SERVER_VD_CIRC: OnceLock<Arc<Circuit>> = OnceLock::new();

#[derive(Debug)]
pub(crate) struct Randoms {
    pub(crate) client_random: ValueRef,
    pub(crate) server_random: ValueRef,
}

#[derive(Debug, Clone)]
pub(crate) struct HashState {
    pub(crate) ms_outer_hash_state: ValueRef,
    pub(crate) ms_inner_hash_state: ValueRef,
}

#[derive(Debug)]
pub(crate) struct VerifyData {
    pub(crate) handshake_hash: ValueRef,
    pub(crate) vd: ValueRef,
}

#[derive(Debug)]
pub(crate) enum State {
    Initialized,
    SessionKeys {
        pms: ValueRef,
        randoms: Randoms,
        hash_state: HashState,
        keys: crate::SessionKeys,
        cf_vd: VerifyData,
        sf_vd: VerifyData,
    },
    ClientFinished {
        hash_state: HashState,
        cf_vd: VerifyData,
        sf_vd: VerifyData,
    },
    ServerFinished {
        hash_state: HashState,
        sf_vd: VerifyData,
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
pub struct MpcPrf<E> {
    config: PrfConfig,
    state: State,
    thread_0: E,
    thread_1: E,
}

impl<E> Debug for MpcPrf<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcPrf")
            .field("config", &self.config)
            .field("state", &self.state)
            .finish()
    }
}

impl<E> MpcPrf<E>
where
    E: Load + Memory + Execute + Decode + Send,
{
    /// Creates a new instance of the PRF.
    pub fn new(config: PrfConfig, thread_0: E, thread_1: E) -> MpcPrf<E> {
        MpcPrf {
            config,
            state: State::Initialized,
            thread_0,
            thread_1,
        }
    }

    /// Returns a mutable reference to the MPC thread.
    pub fn thread_mut(&mut self) -> &mut E {
        &mut self.thread_0
    }

    /// Executes a circuit which computes TLS session keys.
    #[instrument(level = "debug", skip_all, err)]
    async fn execute_session_keys(
        &mut self,
        server_random: [u8; 32],
    ) -> Result<SessionKeys, PrfError> {
        let State::SessionKeys {
            pms,
            randoms: randoms_refs,
            hash_state,
            keys,
            cf_vd,
            sf_vd,
        } = self.state.take()
        else {
            return Err(PrfError::state("session keys not initialized"));
        };

        let circ = SESSION_KEYS_CIRC
            .get()
            .expect("session keys circuit is set");

        self.thread_0
            .assign(&randoms_refs.server_random, server_random)?;

        self.thread_0
            .execute(
                circ.clone(),
                &[pms, randoms_refs.client_random, randoms_refs.server_random],
                &[
                    keys.client_write_key.clone(),
                    keys.server_write_key.clone(),
                    keys.client_iv.clone(),
                    keys.server_iv.clone(),
                    hash_state.ms_outer_hash_state.clone(),
                    hash_state.ms_inner_hash_state.clone(),
                ],
            )
            .await?;

        self.state = State::ClientFinished {
            hash_state,
            cf_vd,
            sf_vd,
        };

        Ok(keys)
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn execute_cf_vd(&mut self, handshake_hash: [u8; 32]) -> Result<[u8; 12], PrfError> {
        let State::ClientFinished {
            hash_state,
            cf_vd,
            sf_vd,
        } = self.state.take()
        else {
            return Err(PrfError::state("PRF not in client finished state"));
        };

        let circ = CLIENT_VD_CIRC.get().expect("client vd circuit is set");

        self.thread_0
            .assign(&cf_vd.handshake_hash, handshake_hash)?;

        self.thread_0
            .execute(
                circ.clone(),
                &[
                    hash_state.ms_outer_hash_state.clone(),
                    hash_state.ms_inner_hash_state.clone(),
                    cf_vd.handshake_hash,
                ],
                &[cf_vd.vd.clone()],
            )
            .await?;

        let mut outputs = self.thread_0.decode(&[cf_vd.vd]).await?;
        let vd: [u8; 12] = outputs.remove(0).try_into().expect("vd is 12 bytes");

        self.state = State::ServerFinished { hash_state, sf_vd };

        Ok(vd)
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn execute_sf_vd(&mut self, handshake_hash: [u8; 32]) -> Result<[u8; 12], PrfError> {
        let State::ServerFinished { hash_state, sf_vd } = self.state.take() else {
            return Err(PrfError::state("PRF not in server finished state"));
        };

        let circ = SERVER_VD_CIRC.get().expect("server vd circuit is set");

        self.thread_0
            .assign(&sf_vd.handshake_hash, handshake_hash)?;

        self.thread_0
            .execute(
                circ.clone(),
                &[
                    hash_state.ms_outer_hash_state,
                    hash_state.ms_inner_hash_state,
                    sf_vd.handshake_hash,
                ],
                &[sf_vd.vd.clone()],
            )
            .await?;

        let mut outputs = self.thread_0.decode(&[sf_vd.vd]).await?;
        let vd: [u8; 12] = outputs.remove(0).try_into().expect("vd is 12 bytes");

        self.state = State::Complete;

        Ok(vd)
    }
}

#[async_trait]
impl<E> Prf for MpcPrf<E>
where
    E: Memory + Load + Execute + Decode + Send,
{
    #[instrument(level = "debug", skip_all, err)]
    async fn setup(&mut self, pms: ValueRef) -> Result<SessionKeys, PrfError> {
        let State::Initialized = self.state.take() else {
            return Err(PrfError::state("PRF not in initialized state"));
        };

        let thread = &mut self.thread_0;

        let randoms = Randoms {
            // The client random is kept private so that the handshake transcript
            // hashes do not leak information about the server's identity.
            client_random: thread.new_input::<[u8; 32]>(
                "client_random",
                match self.config.role {
                    Role::Leader => Visibility::Private,
                    Role::Follower => Visibility::Blind,
                },
            )?,
            server_random: thread.new_input::<[u8; 32]>("server_random", Visibility::Public)?,
        };

        let keys = SessionKeys {
            client_write_key: thread.new_output::<[u8; 16]>("client_write_key")?,
            server_write_key: thread.new_output::<[u8; 16]>("server_write_key")?,
            client_iv: thread.new_output::<[u8; 4]>("client_write_iv")?,
            server_iv: thread.new_output::<[u8; 4]>("server_write_iv")?,
        };

        let hash_state = HashState {
            ms_outer_hash_state: thread.new_output::<[u32; 8]>("ms_outer_hash_state")?,
            ms_inner_hash_state: thread.new_output::<[u32; 8]>("ms_inner_hash_state")?,
        };

        let cf_vd = VerifyData {
            handshake_hash: thread.new_input::<[u8; 32]>("cf_hash", Visibility::Public)?,
            vd: thread.new_output::<[u8; 12]>("cf_vd")?,
        };

        let sf_vd = VerifyData {
            handshake_hash: thread.new_input::<[u8; 32]>("sf_hash", Visibility::Public)?,
            vd: thread.new_output::<[u8; 12]>("sf_vd")?,
        };

        self.state = State::SessionKeys {
            pms,
            randoms,
            hash_state,
            keys: keys.clone(),
            cf_vd,
            sf_vd,
        };

        Ok(keys)
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn set_client_random(&mut self, client_random: Option<[u8; 32]>) -> Result<(), PrfError> {
        let State::SessionKeys { randoms, .. } = &self.state else {
            return Err(PrfError::state("PRF not set up"));
        };

        if self.config.role == Role::Leader {
            let Some(client_random) = client_random else {
                return Err(PrfError::role("leader must provide client random"));
            };

            self.thread_0
                .assign(&randoms.client_random, client_random)?;
        } else if client_random.is_some() {
            return Err(PrfError::role("only leader can set client random"));
        }

        self.thread_0
            .commit(&[randoms.client_random.clone()])
            .await?;

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn preprocess(&mut self) -> Result<(), PrfError> {
        let State::SessionKeys {
            pms,
            randoms,
            hash_state,
            keys,
            cf_vd,
            sf_vd,
        } = self.state.take()
        else {
            return Err(PrfError::state("PRF not set up"));
        };

        // Builds all circuits in parallel and preprocesses the session keys circuit.
        futures::try_join!(
            async {
                if SESSION_KEYS_CIRC.get().is_none() {
                    _ = SESSION_KEYS_CIRC.set(CpuBackend::blocking(build_session_keys).await);
                }

                let circ = SESSION_KEYS_CIRC
                    .get()
                    .expect("session keys circuit should be built");

                self.thread_0
                    .load(
                        circ.clone(),
                        &[
                            pms.clone(),
                            randoms.client_random.clone(),
                            randoms.server_random.clone(),
                        ],
                        &[
                            keys.client_write_key.clone(),
                            keys.server_write_key.clone(),
                            keys.client_iv.clone(),
                            keys.server_iv.clone(),
                            hash_state.ms_outer_hash_state.clone(),
                            hash_state.ms_inner_hash_state.clone(),
                        ],
                    )
                    .await?;

                Ok::<_, PrfError>(())
            },
            async {
                if CLIENT_VD_CIRC.get().is_none() {
                    _ = CLIENT_VD_CIRC
                        .set(CpuBackend::blocking(move || build_verify_data(CF_LABEL)).await);
                }

                Ok::<_, PrfError>(())
            },
            async {
                if SERVER_VD_CIRC.get().is_none() {
                    _ = SERVER_VD_CIRC
                        .set(CpuBackend::blocking(move || build_verify_data(SF_LABEL)).await);
                }

                Ok::<_, PrfError>(())
            }
        )?;

        // Finishes preprocessing the verify data circuits.
        futures::try_join!(
            async {
                self.thread_0
                    .load(
                        CLIENT_VD_CIRC
                            .get()
                            .expect("client finished circuit should be built")
                            .clone(),
                        &[
                            hash_state.ms_outer_hash_state.clone(),
                            hash_state.ms_inner_hash_state.clone(),
                            cf_vd.handshake_hash.clone(),
                        ],
                        &[cf_vd.vd.clone()],
                    )
                    .await
            },
            async {
                self.thread_1
                    .load(
                        SERVER_VD_CIRC
                            .get()
                            .expect("server finished circuit should be built")
                            .clone(),
                        &[
                            hash_state.ms_outer_hash_state.clone(),
                            hash_state.ms_inner_hash_state.clone(),
                            sf_vd.handshake_hash.clone(),
                        ],
                        &[sf_vd.vd.clone()],
                    )
                    .await
            }
        )?;

        self.state = State::SessionKeys {
            pms,
            randoms,
            hash_state,
            keys,
            cf_vd,
            sf_vd,
        };

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn compute_client_finished_vd(
        &mut self,
        handshake_hash: [u8; 32],
    ) -> Result<[u8; 12], PrfError> {
        self.execute_cf_vd(handshake_hash).await
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn compute_server_finished_vd(
        &mut self,
        handshake_hash: [u8; 32],
    ) -> Result<[u8; 12], PrfError> {
        self.execute_sf_vd(handshake_hash).await
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn compute_session_keys(
        &mut self,
        server_random: [u8; 32],
    ) -> Result<SessionKeys, PrfError> {
        self.execute_session_keys(server_random).await
    }
}
