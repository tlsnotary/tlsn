use std::{marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use futures::{lock::Mutex, SinkExt, StreamExt};

use hmac_sha256_core::{
    self as leader_core, PRFLeaderConfig, PRFMessage, PmsLabels, SessionKeyLabels, MS, PMS,
    SESSION_KEYS,
};
use leader_core::{MasterSecretStateLabels, Role, CF_VD, SF_VD};
use mpc_aio::protocol::garble::{exec::dual::DEExecute, factory::GCFactoryError};
use mpc_core::garble::{
    exec::dual::{DualExConfig, DualExConfigBuilder},
    ChaChaEncoder,
};
use utils_aio::{expect_msg_or_err, factory::AsyncFactory};

use crate::{circuits, PRFLeader};

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

pub struct DEPRFLeader<DEF, DE>
where
    DEF: AsyncFactory<DE, Config = DualExConfig, Error = GCFactoryError>,
    DE: DEExecute + Send,
{
    config: PRFLeaderConfig,
    state: State,
    channel: PRFChannel,

    encoder: Option<Arc<Mutex<ChaChaEncoder>>>,

    de_factory: DEF,

    _de: PhantomData<DE>,
}

impl<DEF, DE> DEPRFLeader<DEF, DE>
where
    DEF: AsyncFactory<DE, Config = DualExConfig, Error = GCFactoryError> + Send,
    DE: DEExecute + Send,
{
    pub fn new(
        config: PRFLeaderConfig,
        channel: PRFChannel,
        de_factory: DEF,
    ) -> DEPRFLeader<DEF, DE> {
        DEPRFLeader {
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

    /// Computes leader's shares of the TLS session keys using the session randoms and their
    /// share of the PMS
    ///
    /// Returns session key shares
    pub async fn compute_session_keys(
        &mut self,
        client_random: [u8; 32],
        server_random: [u8; 32],
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

        // Execute C1
        let pms_inner_hash_state =
            circuits::execute_pms(de_pms, Role::Leader, pms_share_labels).await?;

        let (msg, core) =
            leader_core::PRFLeader::new().next(client_random, server_random, pms_inner_hash_state);

        self.channel.send(PRFMessage::LeaderMs1(msg)).await?;

        let msg = expect_msg_or_err!(
            self.channel.next().await,
            PRFMessage::FollowerMs1,
            PRFError::UnexpectedMessage
        )?;
        let (msg, core) = core.next(msg);
        self.channel.send(PRFMessage::LeaderMs2(msg)).await?;

        let msg = expect_msg_or_err!(
            self.channel.next().await,
            PRFMessage::FollowerMs2,
            PRFError::UnexpectedMessage
        )?;
        let (msg, core) = core.next(msg);
        self.channel.send(PRFMessage::LeaderMs3(msg)).await?;

        let p1_inner_hash = core.p1_inner_hash();

        let (ms_inner_hash_state, ms_hash_state_labels) =
            circuits::leader_ms(de_ms, p1_inner_hash).await?;

        let (msg, core) = core.next().next(ms_inner_hash_state);
        self.channel.send(PRFMessage::LeaderKe1(msg)).await?;

        let msg = expect_msg_or_err!(
            self.channel.next().await,
            PRFMessage::FollowerKe1,
            PRFError::UnexpectedMessage
        )?;
        let (msg, core) = core.next(msg);
        self.channel.send(PRFMessage::LeaderKe2(msg)).await?;

        let msg = expect_msg_or_err!(
            self.channel.next().await,
            PRFMessage::FollowerKe2,
            PRFError::UnexpectedMessage
        )?;
        let core = core.next(msg);
        let p1_inner_hash = core.p1_inner_hash();
        let p2_inner_hash = core.p2_inner_hash();

        let session_key_labels = circuits::leader_session_keys(
            de_ke,
            encoder,
            self.config.encoder_default_stream_id(),
            p1_inner_hash,
            p2_inner_hash,
        )
        .await?;

        self.state = State::ClientFinished {
            ms_hash_state_labels,
        };

        Ok(session_key_labels)
    }

    pub async fn compute_client_finished_vd(
        &mut self,
        handshake_hash: [u8; 32],
    ) -> Result<[u8; 12], PRFError> {
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

        let vd =
            circuits::leader_verify_data(de_cf, circ, ms_hash_state_labels.clone(), handshake_hash)
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

        let vd =
            circuits::leader_verify_data(de_sf, circ, ms_hash_state_labels.clone(), handshake_hash)
                .await?;

        self.state = State::Complete;

        Ok(vd)
    }
}

#[async_trait]
impl<DEF, DE> PRFLeader for DEPRFLeader<DEF, DE>
where
    DEF: AsyncFactory<DE, Config = DualExConfig, Error = GCFactoryError> + Send,
    DE: DEExecute + Send,
{
    async fn compute_session_keys(
        &mut self,
        client_random: [u8; 32],
        server_random: [u8; 32],
        pms_share_labels: PmsLabels,
    ) -> Result<SessionKeyLabels, PRFError> {
        self.compute_session_keys(client_random, server_random, pms_share_labels)
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
