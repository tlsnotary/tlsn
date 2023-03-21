use std::{marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use futures::lock::Mutex;

use hmac_sha256_core::{
    self as leader_core, PRFLeaderConfig, PmsLabels, SessionKeyLabels, MS, SESSION_KEYS,
};
use leader_core::{CF_VD, SF_VD};
use mpc_aio::protocol::garble::{exec::dual::DEExecute, factory::GCFactoryError};
use mpc_core::garble::{
    exec::dual::{DualExConfig, DualExConfigBuilder},
    ChaChaEncoder,
};
use utils_aio::factory::AsyncFactory;

use crate::{circuits, PRFLead, State};

use super::PRFError;

pub struct PRFLeader<DEF, DE>
where
    DEF: AsyncFactory<DE, Config = DualExConfig, Error = GCFactoryError>,
    DE: DEExecute + Send,
{
    config: PRFLeaderConfig,
    state: State,

    encoder: Option<Arc<Mutex<ChaChaEncoder>>>,

    de_factory: DEF,

    _de: PhantomData<DE>,
}

impl<DEF, DE> PRFLeader<DEF, DE>
where
    DEF: AsyncFactory<DE, Config = DualExConfig, Error = GCFactoryError> + Send,
    DE: DEExecute + Send,
{
    pub fn new(config: PRFLeaderConfig, de_factory: DEF) -> PRFLeader<DEF, DE> {
        PRFLeader {
            config,
            state: State::SessionKeys,
            encoder: None,
            de_factory,
            _de: PhantomData,
        }
    }

    pub fn set_encoder(&mut self, encoder: Arc<Mutex<ChaChaEncoder>>) {
        self.encoder = Some(encoder);
    }

    /// Computes leader's shares of the TLS session keys using the session randoms and their
    /// share of the PMS
    ///
    /// Returns session key shares
    pub async fn compute_session_keys(
        &mut self,
        client_random: [u8; 32],
        server_random: [u8; 32],
        pms_labels: PmsLabels,
    ) -> Result<SessionKeyLabels, PRFError> {
        let state = std::mem::replace(&mut self.state, State::Error);
        let encoder = self.encoder.clone().ok_or(PRFError::EncoderNotSet)?;

        let State::SessionKeys = state else {
            return Err(PRFError::InvalidState(state));
        };

        // TODO: Set up this stuff concurrently
        let id = format!("{}/ms", self.config.id());
        let de_config = DualExConfigBuilder::default()
            .id(id.clone())
            .circ(MS.clone())
            .build()
            .expect("DualExConfig should be valid");
        let de_ms = self.de_factory.create(id, de_config).await?;

        let id = format!("{}/ke", self.config.id());
        let de_config = DualExConfigBuilder::default()
            .id(id.clone())
            .circ(SESSION_KEYS.clone())
            .build()
            .expect("DualExConfig should be valid");
        let de_ke = self.de_factory.create(id, de_config).await?;

        let ms_state_labels = circuits::leader_ms(
            de_ms,
            encoder,
            self.config.encoder_default_stream_id(),
            pms_labels,
            client_random,
            server_random,
        )
        .await?;

        let session_key_labels = circuits::session_keys(de_ke, ms_state_labels.clone()).await?;

        self.state = State::ClientFinished {
            ms_hash_state_labels: ms_state_labels,
        };

        Ok(session_key_labels)
    }

    pub async fn compute_client_finished_vd(
        &mut self,
        handshake_hash: [u8; 32],
    ) -> Result<[u8; 12], PRFError> {
        let state = std::mem::replace(&mut self.state, State::Error);
        let encoder = self.encoder.clone().ok_or(PRFError::EncoderNotSet)?;

        let State::ClientFinished { ms_hash_state_labels } = state else {
            return Err(PRFError::InvalidState(state));
        };

        let id = format!("{}/cf", self.config.id());
        let de_config = DualExConfigBuilder::default()
            .id(id.clone())
            .circ(CF_VD.clone())
            .build()
            .expect("DualExConfig should be valid");
        let de_cf = self.de_factory.create(id, de_config).await?;

        let vd = circuits::leader_verify_data(
            de_cf,
            &CF_VD,
            encoder,
            self.config.encoder_default_stream_id(),
            ms_hash_state_labels.clone(),
            handshake_hash,
        )
        .await?;

        self.state = State::ServerFinished {
            ms_hash_state_labels,
        };

        Ok(vd)
    }

    pub async fn compute_server_finished_vd(
        &mut self,
        handshake_hash: [u8; 32],
    ) -> Result<[u8; 12], PRFError> {
        let state = std::mem::replace(&mut self.state, State::Error);
        let encoder = self.encoder.clone().ok_or(PRFError::EncoderNotSet)?;

        let State::ServerFinished { ms_hash_state_labels } = state else {
            return Err(PRFError::InvalidState(state));
        };

        let id = format!("{}/sf", self.config.id());
        let de_config = DualExConfigBuilder::default()
            .id(id.clone())
            .circ(SF_VD.clone())
            .build()
            .expect("DualExConfig should be valid");
        let de_sf = self.de_factory.create(id, de_config).await?;

        let vd = circuits::leader_verify_data(
            de_sf,
            &SF_VD,
            encoder,
            self.config.encoder_default_stream_id(),
            ms_hash_state_labels.clone(),
            handshake_hash,
        )
        .await?;

        self.state = State::Complete;

        Ok(vd)
    }
}

#[async_trait]
impl<DEF, DE> PRFLead for PRFLeader<DEF, DE>
where
    DEF: AsyncFactory<DE, Config = DualExConfig, Error = GCFactoryError> + Send,
    DE: DEExecute + Send,
{
    async fn compute_session_keys(
        &mut self,
        client_random: [u8; 32],
        server_random: [u8; 32],
        pms_labels: PmsLabels,
    ) -> Result<SessionKeyLabels, PRFError> {
        self.compute_session_keys(client_random, server_random, pms_labels)
            .await
    }

    async fn compute_client_finished_vd(
        &mut self,
        handshake_hash: [u8; 32],
    ) -> Result<[u8; 12], PRFError> {
        self.compute_client_finished_vd(handshake_hash).await
    }

    async fn compute_server_finished_vd(
        &mut self,
        handshake_hash: [u8; 32],
    ) -> Result<[u8; 12], PRFError> {
        self.compute_server_finished_vd(handshake_hash).await
    }
}
