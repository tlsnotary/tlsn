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

enum Msg {
    Cf,
    Sf,
}

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
        randoms: Option<([u8; 32], [u8; 32])>,
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

        if let Some((client_random, server_random)) = randoms {
            self.thread_0
                .assign(&randoms_refs.client_random, client_random)?;
            self.thread_0
                .assign(&randoms_refs.server_random, server_random)?;
        }

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
    async fn execute_cf_vd(
        &mut self,
        handshake_hash: Option<[u8; 32]>,
    ) -> Result<[u8; 12], PrfError> {
        let State::ClientFinished {
            hash_state,
            cf_vd,
            sf_vd,
        } = self.state.take()
        else {
            return Err(PrfError::state("PRF not in client finished state"));
        };

        let circ = CLIENT_VD_CIRC.get().expect("client vd circuit is set");

        if let Some(handshake_hash) = handshake_hash {
            self.thread_0
                .assign(&cf_vd.handshake_hash, handshake_hash)?;
        }

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
    async fn execute_sf_vd(
        &mut self,
        handshake_hash: Option<[u8; 32]>,
    ) -> Result<[u8; 12], PrfError> {
        let State::ServerFinished { hash_state, sf_vd } = self.state.take() else {
            return Err(PrfError::state("PRF not in server finished state"));
        };

        let circ = SERVER_VD_CIRC.get().expect("server vd circuit is set");

        if let Some(handshake_hash) = handshake_hash {
            self.thread_0
                .assign(&sf_vd.handshake_hash, handshake_hash)?;
        }

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
    async fn preprocess(&mut self, pms: ValueRef) -> Result<SessionKeys, PrfError> {
        let State::Initialized = self.state.take() else {
            return Err(PrfError::state("PRF not in initialized state"));
        };

        let visibility = match self.config.role {
            Role::Leader => Visibility::Private,
            Role::Follower => Visibility::Blind,
        };

        // Perform pre-computation for all circuits.
        let (randoms, hash_state, keys) =
            setup_session_keys(&mut self.thread_0, pms.clone(), visibility).await?;

        let (cf_vd, sf_vd) = futures::try_join!(
            setup_finished_msg(&mut self.thread_0, Msg::Cf, hash_state.clone(), visibility),
            setup_finished_msg(&mut self.thread_1, Msg::Sf, hash_state.clone(), visibility),
        )?;

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
    async fn compute_client_finished_vd(
        &mut self,
        handshake_hash: Option<[u8; 32]>,
    ) -> Result<[u8; 12], PrfError> {
        if (self.config.role != Role::Leader) && handshake_hash.is_some() {
            return Err(PrfError::role("only leader can provide handshake hash"));
        }

        self.execute_cf_vd(handshake_hash).await
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn compute_server_finished_vd(
        &mut self,
        handshake_hash: Option<[u8; 32]>,
    ) -> Result<[u8; 12], PrfError> {
        if (self.config.role != Role::Leader) && handshake_hash.is_some() {
            return Err(PrfError::role("only leader can provide handshake hash"));
        }

        self.execute_sf_vd(handshake_hash).await
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn compute_session_keys_private(
        &mut self,
        client_random: [u8; 32],
        server_random: [u8; 32],
    ) -> Result<SessionKeys, PrfError> {
        if self.config.role != Role::Leader {
            return Err(PrfError::role("only leader can provide inputs"));
        }

        self.execute_session_keys(Some((client_random, server_random)))
            .await
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn compute_session_keys_blind(&mut self) -> Result<SessionKeys, PrfError> {
        if self.config.role != Role::Follower {
            return Err(PrfError::role("leader must provide inputs"));
        }

        self.execute_session_keys(None).await
    }
}

async fn setup_session_keys<T: Memory + Load + Send>(
    thread: &mut T,
    pms: ValueRef,
    visibility: Visibility,
) -> Result<(Randoms, HashState, SessionKeys), PrfError> {
    let client_random = thread.new_input::<[u8; 32]>("client_finished", visibility)?;
    let server_random = thread.new_input::<[u8; 32]>("server_finished", visibility)?;

    let client_write_key = thread.new_output::<[u8; 16]>("client_write_key")?;
    let server_write_key = thread.new_output::<[u8; 16]>("server_write_key")?;
    let client_iv = thread.new_output::<[u8; 4]>("client_write_iv")?;
    let server_iv = thread.new_output::<[u8; 4]>("server_write_iv")?;

    let ms_outer_hash_state = thread.new_output::<[u32; 8]>("ms_outer_hash_state")?;
    let ms_inner_hash_state = thread.new_output::<[u32; 8]>("ms_inner_hash_state")?;

    if SESSION_KEYS_CIRC.get().is_none() {
        _ = SESSION_KEYS_CIRC.set(CpuBackend::blocking(build_session_keys).await);
    }

    let circ = SESSION_KEYS_CIRC
        .get()
        .expect("session keys circuit is set");

    thread
        .load(
            circ.clone(),
            &[pms, client_random.clone(), server_random.clone()],
            &[
                client_write_key.clone(),
                server_write_key.clone(),
                client_iv.clone(),
                server_iv.clone(),
                ms_outer_hash_state.clone(),
                ms_inner_hash_state.clone(),
            ],
        )
        .await?;

    Ok((
        Randoms {
            client_random,
            server_random,
        },
        HashState {
            ms_outer_hash_state,
            ms_inner_hash_state,
        },
        SessionKeys {
            client_write_key,
            server_write_key,
            client_iv,
            server_iv,
        },
    ))
}

async fn setup_finished_msg<T: Memory + Load + Send>(
    thread: &mut T,
    msg: Msg,
    hash_state: HashState,
    visibility: Visibility,
) -> Result<VerifyData, PrfError> {
    let name = match msg {
        Msg::Cf => String::from("client_finished"),
        Msg::Sf => String::from("server_finished"),
    };

    let handshake_hash =
        thread.new_input::<[u8; 32]>(&format!("{name}/handshake_hash"), visibility)?;
    let vd = thread.new_output::<[u8; 12]>(&format!("{name}/vd"))?;

    let circ = match msg {
        Msg::Cf => &CLIENT_VD_CIRC,
        Msg::Sf => &SERVER_VD_CIRC,
    };

    let label = match msg {
        Msg::Cf => CF_LABEL,
        Msg::Sf => SF_LABEL,
    };

    if circ.get().is_none() {
        _ = circ.set(CpuBackend::blocking(move || build_verify_data(label)).await);
    }

    let circ = circ.get().expect("session keys circuit is set");

    thread
        .load(
            circ.clone(),
            &[
                hash_state.ms_outer_hash_state,
                hash_state.ms_inner_hash_state,
                handshake_hash.clone(),
            ],
            &[vd.clone()],
        )
        .await?;

    Ok(VerifyData { handshake_hash, vd })
}
