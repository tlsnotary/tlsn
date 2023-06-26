use async_trait::async_trait;

use hmac_sha256_circuits::{build_session_keys, build_verify_data};
use mpz_garble::{Decode, DecodePrivate, Execute, Memory, ValueRef};
use std::fmt::Debug;

use crate::{Prf, PrfError, SessionKeys};

/// MPC PRF for computing TLS HMAC-SHA256 PRF.
pub struct MpcPrf<E>
where
    E: Memory + Execute + DecodePrivate,
{
    state: State,
    executor: E,
}

impl<E: Memory + Execute + DecodePrivate> Debug for MpcPrf<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcPrf")
            .field("state", &self.state)
            .field("executor", &"{{ ... }}")
            .finish()
    }
}

/// Internal state of [MpcPrf].
#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub enum State {
    SessionKeys,
    ClientFinished {
        ms_outer_hash_state: ValueRef,
        ms_inner_hash_state: ValueRef,
    },
    ServerFinished {
        ms_outer_hash_state: ValueRef,
        ms_inner_hash_state: ValueRef,
    },
    Complete,
    Error,
}

impl<E> MpcPrf<E>
where
    E: Memory + Execute + Decode + DecodePrivate,
{
    /// Creates a new instance of the PRF.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "info", skip(executor), ret)
    )]
    pub fn new(executor: E) -> MpcPrf<E> {
        MpcPrf {
            state: State::SessionKeys,
            executor,
        }
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "debug", skip(self), err)
    )]
    async fn internal_compute_session_keys(
        &mut self,
        client_random: Option<[u8; 32]>,
        server_random: Option<[u8; 32]>,
        pms: ValueRef,
    ) -> Result<SessionKeys, PrfError> {
        let state = std::mem::replace(&mut self.state, State::Error);

        let State::SessionKeys = state else {
            return Err(PrfError::InvalidState(state));
        };

        let client_random = self
            .executor
            .new_private_input("client_random", client_random)?;
        let server_random = self
            .executor
            .new_private_input("server_random", server_random)?;

        let client_write_key = self.executor.new_output::<[u8; 16]>("client_write_key")?;
        let server_write_key = self.executor.new_output::<[u8; 16]>("server_write_key")?;
        let client_iv = self.executor.new_output::<[u8; 4]>("client_write_iv")?;
        let server_iv = self.executor.new_output::<[u8; 4]>("server_write_iv")?;
        let ms_outer_hash_state = self
            .executor
            .new_output::<[u32; 8]>("ms_outer_hash_state")?;
        let ms_inner_hash_state = self
            .executor
            .new_output::<[u32; 8]>("ms_inner_hash_state")?;

        self.executor
            .execute(
                build_session_keys(),
                &[pms, client_random, server_random],
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

        self.state = State::ClientFinished {
            ms_outer_hash_state,
            ms_inner_hash_state,
        };

        Ok(SessionKeys {
            client_write_key,
            server_write_key,
            client_iv,
            server_iv,
        })
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "debug", skip(self, label), err)
    )]
    async fn internal_compute_vd(
        &mut self,
        label: &str,
        handshake_hash: Option<[u8; 32]>,
        outer_state: ValueRef,
        inner_state: ValueRef,
    ) -> Result<Option<[u8; 12]>, PrfError> {
        let handshake_hash_value = self
            .executor
            .new_private_input(&format!("prf_label/{}/hash", label), handshake_hash)?;
        let vd = self
            .executor
            .new_output::<[u8; 12]>(&format!("prf_label/{}/vd", label))?;

        self.executor
            .execute(
                build_verify_data(label.as_bytes()),
                &[outer_state, inner_state, handshake_hash_value],
                &[vd.clone()],
            )
            .await?;

        if handshake_hash.is_some() {
            let mut outputs = self.executor.decode_private(&[vd]).await?;

            let vd: [u8; 12] = outputs.remove(0).try_into().expect("vd is 12 bytes");

            Ok(Some(vd))
        } else {
            self.executor.decode_blind(&[vd]).await?;

            Ok(None)
        }
    }
}

#[async_trait]
impl<E> Prf for MpcPrf<E>
where
    E: Memory + Execute + Decode + DecodePrivate + Send,
{
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "debug", skip(self), err)
    )]
    async fn compute_session_keys_private(
        &mut self,
        client_random: [u8; 32],
        server_random: [u8; 32],
        pms: ValueRef,
    ) -> Result<SessionKeys, PrfError> {
        self.internal_compute_session_keys(Some(client_random), Some(server_random), pms)
            .await
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "debug", skip(self, handshake_hash), err)
    )]
    async fn compute_client_finished_vd_private(
        &mut self,
        handshake_hash: [u8; 32],
    ) -> Result<[u8; 12], PrfError> {
        let state = std::mem::replace(&mut self.state, State::Error);

        let State::ClientFinished { ms_outer_hash_state, ms_inner_hash_state } = state else {
            return Err(PrfError::InvalidState(state));
        };

        let vd = self
            .internal_compute_vd(
                "client finished",
                Some(handshake_hash),
                ms_outer_hash_state.clone(),
                ms_inner_hash_state.clone(),
            )
            .await?
            .unwrap();

        self.state = State::ServerFinished {
            ms_outer_hash_state,
            ms_inner_hash_state,
        };

        Ok(vd)
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "debug", skip(self), err)
    )]
    async fn compute_server_finished_vd_private(
        &mut self,
        handshake_hash: [u8; 32],
    ) -> Result<[u8; 12], PrfError> {
        let state = std::mem::replace(&mut self.state, State::Error);

        let State::ServerFinished { ms_outer_hash_state, ms_inner_hash_state } = state else {
            return Err(PrfError::InvalidState(state));
        };

        let vd = self
            .internal_compute_vd(
                "server finished",
                Some(handshake_hash),
                ms_outer_hash_state.clone(),
                ms_inner_hash_state.clone(),
            )
            .await?
            .unwrap();

        self.state = State::Complete;

        Ok(vd)
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "debug", skip(self), err)
    )]
    async fn compute_session_keys_blind(&mut self, pms: ValueRef) -> Result<SessionKeys, PrfError> {
        self.internal_compute_session_keys(None, None, pms).await
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "debug", skip(self), err)
    )]
    async fn compute_client_finished_vd_blind(&mut self) -> Result<(), PrfError> {
        let state = std::mem::replace(&mut self.state, State::Error);

        let State::ClientFinished { ms_outer_hash_state, ms_inner_hash_state } = state else {
            return Err(PrfError::InvalidState(state));
        };

        _ = self
            .internal_compute_vd(
                "client finished",
                None,
                ms_outer_hash_state.clone(),
                ms_inner_hash_state.clone(),
            )
            .await?;

        self.state = State::ServerFinished {
            ms_outer_hash_state,
            ms_inner_hash_state,
        };

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "debug", skip(self), err)
    )]
    async fn compute_server_finished_vd_blind(&mut self) -> Result<(), PrfError> {
        let state = std::mem::replace(&mut self.state, State::Error);

        let State::ServerFinished { ms_outer_hash_state, ms_inner_hash_state } = state else {
            return Err(PrfError::InvalidState(state));
        };

        _ = self
            .internal_compute_vd(
                "server finished",
                None,
                ms_outer_hash_state.clone(),
                ms_inner_hash_state.clone(),
            )
            .await?;

        self.state = State::Complete;

        Ok(())
    }
}
