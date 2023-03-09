use std::{marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use follower_core::{Role, CF_VD, SF_VD};
use futures::{lock::Mutex, SinkExt, StreamExt};

use hmac_sha256_core::{
    self as follower_core, MasterSecretStateLabels, PRFFollowerConfig, PRFMessage, PmsLabels,
    SessionKeyLabels, MS, PMS, SESSION_KEYS,
};
use mpc_aio::protocol::garble::{exec::dual::DEExecute, factory::GCFactoryError};
use mpc_core::garble::{
    exec::dual::{DualExConfig, DualExConfigBuilder},
    ChaChaEncoder,
};
use utils_aio::{expect_msg_or_err, factory::AsyncFactory};

use crate::{circuits, PRFFollower};

use super::{PRFChannel, PRFError};

enum State {
    MasterSecret,
    ClientFinished {
        ms_hash_state_labels: MasterSecretStateLabels,
    },
    ServerFinished {
        ms_hash_state_labels: MasterSecretStateLabels,
    },
    Complete,
    Error,
}

pub struct DEPRFFollower<DEF, DE>
where
    DEF: AsyncFactory<DE, Config = DualExConfig, Error = GCFactoryError>,
    DE: DEExecute + Send,
{
    config: PRFFollowerConfig,
    state: State,
    channel: PRFChannel,

    encoder: Option<Arc<Mutex<ChaChaEncoder>>>,

    de_factory: DEF,

    _de: PhantomData<DE>,
}

impl<DEF, DE> DEPRFFollower<DEF, DE>
where
    DEF: AsyncFactory<DE, Config = DualExConfig, Error = GCFactoryError> + Send,
    DE: DEExecute + Send,
{
    pub fn new(
        config: PRFFollowerConfig,
        channel: PRFChannel,
        de_factory: DEF,
    ) -> DEPRFFollower<DEF, DE> {
        DEPRFFollower {
            config,
            state: State::MasterSecret,
            channel,
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
        pms_share_labels: PmsLabels,
    ) -> Result<SessionKeyLabels, PRFError> {
        let Some(encoder) = self.encoder.clone().take() else {
            panic!()
        };

        // TODO: Set up this stuff concurrently
        let id = format!("{}/pms", self.config.id());
        let de_config = DualExConfigBuilder::default()
            .id(id.clone())
            .circ(PMS.clone())
            .build()
            .expect("DualExConfig should be valid");
        let de_pms = self.de_factory.create(id, de_config).await?;

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

        let pms_outer_hash_state =
            circuits::execute_pms(de_pms, Role::Follower, pms_share_labels).await?;

        let msg = expect_msg_or_err!(
            self.channel.next().await,
            PRFMessage::LeaderMs1,
            PRFError::UnexpectedMessage
        )?;
        let (msg, core) = follower_core::PRFFollower::new().next(pms_outer_hash_state, msg);

        self.channel.send(PRFMessage::FollowerMs1(msg)).await?;

        let msg = expect_msg_or_err!(
            self.channel.next().await,
            PRFMessage::LeaderMs2,
            PRFError::UnexpectedMessage
        )?;
        let (msg, core) = core.next(msg);
        self.channel.send(PRFMessage::FollowerMs2(msg)).await?;

        let msg = expect_msg_or_err!(
            self.channel.next().await,
            PRFMessage::LeaderMs3,
            PRFError::UnexpectedMessage
        )?;
        let core = core.next(msg);

        let p2 = core.p2();
        let (ms_outer_hash_state, ms_hash_state_labels) =
            circuits::follower_ms(de_ms, pms_outer_hash_state, p2).await?;

        let core = core.next().next(ms_outer_hash_state);

        let msg = expect_msg_or_err!(
            self.channel.next().await,
            PRFMessage::LeaderKe1,
            PRFError::UnexpectedMessage
        )?;
        let (msg, core) = core.next(msg);
        self.channel.send(PRFMessage::FollowerKe1(msg)).await?;

        let msg = expect_msg_or_err!(
            self.channel.next().await,
            PRFMessage::LeaderKe2,
            PRFError::UnexpectedMessage
        )?;
        let msg = core.next(msg);
        self.channel.send(PRFMessage::FollowerKe2(msg)).await?;

        let session_keys = circuits::follower_session_keys(
            de_ke,
            encoder,
            self.config.encoder_default_stream_id(),
            ms_outer_hash_state,
        )
        .await?;

        self.state = State::ClientFinished {
            ms_hash_state_labels,
        };

        Ok(session_keys)
    }

    pub async fn compute_client_finished_vd(&mut self) -> Result<(), PRFError> {
        let state = std::mem::replace(&mut self.state, State::Error);

        let State::ClientFinished { ms_hash_state_labels } = state else {
            panic!()
        };

        let circ = CF_VD.clone();

        let id = format!("{}/cf", self.config.id());
        let de_config = DualExConfigBuilder::default()
            .id(id.clone())
            .circ(circ.clone())
            .build()
            .expect("DualExConfig should be valid");
        let de_cf = self.de_factory.create(id, de_config).await?;

        circuits::follower_verify_data(de_cf, circ, ms_hash_state_labels.clone()).await?;

        self.state = State::ServerFinished {
            ms_hash_state_labels,
        };

        Ok(())
    }

    pub async fn compute_server_finished_vd(&mut self) -> Result<(), PRFError> {
        let state = std::mem::replace(&mut self.state, State::Error);

        let State::ServerFinished { ms_hash_state_labels } = state else {
            panic!()
        };

        let circ = SF_VD.clone();

        let id = format!("{}/sf", self.config.id());
        let de_config = DualExConfigBuilder::default()
            .id(id.clone())
            .circ(circ.clone())
            .build()
            .expect("DualExConfig should be valid");
        let de_sf = self.de_factory.create(id, de_config).await?;

        let circ = SF_VD.clone();
        circuits::follower_verify_data(de_sf, circ, ms_hash_state_labels.clone()).await?;

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
        pms_share_labels: PmsLabels,
    ) -> Result<SessionKeyLabels, PRFError> {
        self.compute_session_keys(pms_share_labels).await
    }

    async fn compute_client_finished_vd(&mut self) -> Result<(), PRFError> {
        self.compute_client_finished_vd().await
    }

    async fn compute_server_finished_vd(&mut self) -> Result<(), PRFError> {
        self.compute_server_finished_vd().await
    }
}
