use std::{
    fmt::Debug,
    sync::{Arc, OnceLock},
};

use async_trait::async_trait;

use hmac_sha256_circuits::{build_session_keys, build_verify_data};
use mpz_circuits::Circuit;
use mpz_garble::{
    config::Visibility, value::ValueRef, Decode, DecodePrivate, Execute, Load, Memory,
};
use utils_aio::non_blocking_backend::{Backend, NonBlockingBackend};

use crate::{Prf, PrfConfig, PrfError, Role, SessionKeys, CF_LABEL, SF_LABEL};

#[cfg(feature = "tracing")]
use tracing::instrument;

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

/// MPC PRF for computing TLS HMAC-SHA256 PRF.
pub struct MpcPrf<E> {
    config: PrfConfig,
    state: state::State,
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
    E: Load + Memory + Execute + DecodePrivate + Send,
{
    /// Creates a new instance of the PRF.
    pub fn new(config: PrfConfig, thread_0: E, thread_1: E) -> MpcPrf<E> {
        MpcPrf {
            config,
            state: state::State::Initialized,
            thread_0,
            thread_1,
        }
    }

    /// Executes a circuit which computes TLS session keys.
    async fn execute_session_keys(
        &mut self,
        randoms: Option<([u8; 32], [u8; 32])>,
    ) -> Result<SessionKeys, PrfError> {
        let state::SessionKeys {
            pms,
            randoms: randoms_refs,
            hash_state,
            keys,
            cf_vd,
            sf_vd,
        } = std::mem::replace(&mut self.state, state::State::Error).try_into_session_keys()?;

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

        self.state = state::State::ClientFinished(state::ClientFinished {
            hash_state,
            cf_vd,
            sf_vd,
        });

        Ok(keys)
    }

    async fn execute_cf_vd(
        &mut self,
        handshake_hash: Option<[u8; 32]>,
    ) -> Result<Option<[u8; 12]>, PrfError> {
        let state::ClientFinished {
            hash_state,
            cf_vd,
            sf_vd,
        } = std::mem::replace(&mut self.state, state::State::Error).try_into_client_finished()?;

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

        let vd = if handshake_hash.is_some() {
            let mut outputs = self.thread_0.decode_private(&[cf_vd.vd]).await?;
            let vd: [u8; 12] = outputs.remove(0).try_into().expect("vd is 12 bytes");

            Some(vd)
        } else {
            self.thread_0.decode_blind(&[cf_vd.vd]).await?;

            None
        };

        self.state = state::State::ServerFinished(state::ServerFinished { hash_state, sf_vd });

        Ok(vd)
    }

    async fn execute_sf_vd(
        &mut self,
        handshake_hash: Option<[u8; 32]>,
    ) -> Result<Option<[u8; 12]>, PrfError> {
        let state::ServerFinished { hash_state, sf_vd } =
            std::mem::replace(&mut self.state, state::State::Error).try_into_server_finished()?;

        let circ = SERVER_VD_CIRC.get().expect("server vd circuit is set");

        if let Some(handshake_hash) = handshake_hash {
            self.thread_1
                .assign(&sf_vd.handshake_hash, handshake_hash)?;
        }

        self.thread_1
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

        let vd = if handshake_hash.is_some() {
            let mut outputs = self.thread_1.decode_private(&[sf_vd.vd]).await?;
            let vd: [u8; 12] = outputs.remove(0).try_into().expect("vd is 12 bytes");

            Some(vd)
        } else {
            self.thread_1.decode_blind(&[sf_vd.vd]).await?;

            None
        };

        self.state = state::State::Complete;

        Ok(vd)
    }
}

#[async_trait]
impl<E> Prf for MpcPrf<E>
where
    E: Memory + Load + Execute + Decode + DecodePrivate + Send,
{
    #[cfg_attr(feature = "tracing", instrument(level = "debug", skip_all, err))]
    async fn setup(&mut self, pms: ValueRef) -> Result<(), PrfError> {
        std::mem::replace(&mut self.state, state::State::Error).try_into_initialized()?;

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

        self.state = state::State::SessionKeys(state::SessionKeys {
            pms,
            randoms,
            hash_state,
            keys,
            cf_vd,
            sf_vd,
        });

        Ok(())
    }

    #[cfg_attr(feature = "tracing", instrument(level = "debug", skip_all, err))]
    async fn compute_session_keys_private(
        &mut self,
        client_random: [u8; 32],
        server_random: [u8; 32],
    ) -> Result<SessionKeys, PrfError> {
        if self.config.role != Role::Leader {
            return Err(PrfError::RoleError(
                "only leader can provide inputs".to_string(),
            ));
        }

        self.execute_session_keys(Some((client_random, server_random)))
            .await
    }

    #[cfg_attr(feature = "tracing", instrument(level = "debug", skip_all, err))]
    async fn compute_client_finished_vd_private(
        &mut self,
        handshake_hash: [u8; 32],
    ) -> Result<[u8; 12], PrfError> {
        if self.config.role != Role::Leader {
            return Err(PrfError::RoleError(
                "only leader can provide inputs".to_string(),
            ));
        }

        self.execute_cf_vd(Some(handshake_hash))
            .await
            .map(|hash| hash.expect("vd is decoded"))
    }

    #[cfg_attr(feature = "tracing", instrument(level = "debug", skip_all, err))]
    async fn compute_server_finished_vd_private(
        &mut self,
        handshake_hash: [u8; 32],
    ) -> Result<[u8; 12], PrfError> {
        if self.config.role != Role::Leader {
            return Err(PrfError::RoleError(
                "only leader can provide inputs".to_string(),
            ));
        }

        self.execute_sf_vd(Some(handshake_hash))
            .await
            .map(|hash| hash.expect("vd is decoded"))
    }

    #[cfg_attr(feature = "tracing", instrument(level = "debug", skip_all, err))]
    async fn compute_session_keys_blind(&mut self) -> Result<SessionKeys, PrfError> {
        if self.config.role != Role::Follower {
            return Err(PrfError::RoleError(
                "leader must provide inputs".to_string(),
            ));
        }

        self.execute_session_keys(None).await
    }

    #[cfg_attr(feature = "tracing", instrument(level = "debug", skip_all, err))]
    async fn compute_client_finished_vd_blind(&mut self) -> Result<(), PrfError> {
        if self.config.role != Role::Follower {
            return Err(PrfError::RoleError(
                "leader must provide inputs".to_string(),
            ));
        }

        self.execute_cf_vd(None).await.map(|_| ())
    }

    #[cfg_attr(feature = "tracing", instrument(level = "debug", skip(self), err))]
    async fn compute_server_finished_vd_blind(&mut self) -> Result<(), PrfError> {
        if self.config.role != Role::Follower {
            return Err(PrfError::RoleError(
                "leader must provide inputs".to_string(),
            ));
        }

        self.execute_sf_vd(None).await.map(|_| ())
    }
}

pub(crate) mod state {
    use super::*;
    use enum_try_as_inner::EnumTryAsInner;

    #[derive(Debug, EnumTryAsInner)]
    #[derive_err(Debug)]
    pub(crate) enum State {
        Initialized,
        SessionKeys(SessionKeys),
        ClientFinished(ClientFinished),
        ServerFinished(ServerFinished),
        Complete,
        Error,
    }

    #[derive(Debug)]
    pub(crate) struct SessionKeys {
        pub(crate) pms: ValueRef,
        pub(crate) randoms: Randoms,
        pub(crate) hash_state: HashState,
        pub(crate) keys: crate::SessionKeys,
        pub(crate) cf_vd: VerifyData,
        pub(crate) sf_vd: VerifyData,
    }

    #[derive(Debug)]
    pub(crate) struct ClientFinished {
        pub(crate) hash_state: HashState,
        pub(crate) cf_vd: VerifyData,
        pub(crate) sf_vd: VerifyData,
    }

    #[derive(Debug)]
    pub(crate) struct ServerFinished {
        pub(crate) hash_state: HashState,
        pub(crate) sf_vd: VerifyData,
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
        _ = SESSION_KEYS_CIRC.set(Backend::spawn(build_session_keys).await);
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
        _ = circ.set(Backend::spawn(move || build_verify_data(label)).await);
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
