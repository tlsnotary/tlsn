use std::{marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use follower_core::{CF_VD, SF_VD};
use futures::lock::Mutex;

use hmac_sha256_core::{
    self as follower_core, PRFFollowerConfig, PmsLabels, SessionKeyLabels, MS, SESSION_KEYS,
};
use mpc_aio::protocol::garble::{exec::dual::DEExecute, factory::GCFactoryError};
use mpc_core::garble::{
    exec::dual::{DualExConfig, DualExConfigBuilder},
    ChaChaEncoder,
};
use utils_aio::factory::AsyncFactory;

use crate::{circuits, PRFFollower, State};

use super::PRFError;

pub struct DEPRFFollower<DEF, DE>
where
    DEF: AsyncFactory<DE, Config = DualExConfig, Error = GCFactoryError>,
    DE: DEExecute + Send,
{
    config: PRFFollowerConfig,
    state: State,

    encoder: Option<Arc<Mutex<ChaChaEncoder>>>,

    de_factory: DEF,

    _de: PhantomData<DE>,
}

impl<DEF, DE> DEPRFFollower<DEF, DE>
where
    DEF: AsyncFactory<DE, Config = DualExConfig, Error = GCFactoryError> + Send,
    DE: DEExecute + Send,
{
    pub fn new(config: PRFFollowerConfig, de_factory: DEF) -> DEPRFFollower<DEF, DE> {
        DEPRFFollower {
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

    pub async fn compute_session_keys(
        &mut self,
        pms_labels: PmsLabels,
    ) -> Result<SessionKeyLabels, PRFError> {
        let state = std::mem::replace(&mut self.state, State::Error);
        let encoder = self.encoder.clone().unwrap();

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

        let ms_state_labels = circuits::follower_ms(
            de_ms,
            encoder,
            self.config.encoder_default_stream_id(),
            pms_labels,
        )
        .await?;

        let session_key_labels = circuits::session_keys(de_ke, ms_state_labels.clone()).await?;

        self.state = State::ClientFinished {
            ms_hash_state_labels: ms_state_labels,
        };

        Ok(session_key_labels)
    }

    pub async fn compute_client_finished_vd(&mut self) -> Result<(), PRFError> {
        let state = std::mem::replace(&mut self.state, State::Error);
        let encoder = self.encoder.clone().unwrap();

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

        circuits::follower_verify_data(
            de_cf,
            &CF_VD,
            encoder,
            self.config.encoder_default_stream_id(),
            ms_hash_state_labels.clone(),
        )
        .await?;

        self.state = State::ServerFinished {
            ms_hash_state_labels,
        };

        Ok(())
    }

    pub async fn compute_server_finished_vd(&mut self) -> Result<(), PRFError> {
        let state = std::mem::replace(&mut self.state, State::Error);
        let encoder = self.encoder.clone().unwrap();

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

        circuits::follower_verify_data(
            de_sf,
            &SF_VD,
            encoder,
            self.config.encoder_default_stream_id(),
            ms_hash_state_labels.clone(),
        )
        .await?;

        self.state = State::Complete;

        Ok(())
    }
}

#[async_trait]
impl<DEF, DE> PRFFollower for DEPRFFollower<DEF, DE>
where
    DEF: AsyncFactory<DE, Config = DualExConfig, Error = GCFactoryError> + Send,
    DE: DEExecute + Send,
{
    async fn compute_session_keys(
        &mut self,
        pms_labels: PmsLabels,
    ) -> Result<SessionKeyLabels, PRFError> {
        self.compute_session_keys(pms_labels).await
    }

    async fn compute_client_finished_vd(&mut self) -> Result<(), PRFError> {
        self.compute_client_finished_vd().await
    }

    async fn compute_server_finished_vd(&mut self) -> Result<(), PRFError> {
        self.compute_server_finished_vd().await
    }
}
