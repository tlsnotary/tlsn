use crate::{
    leader::{LeaderOutput, MpcTlsLeader, State},
    MpcTlsError,
};
use async_trait::async_trait;
use ludi::{mailbox, Actor, Address, Context as LudiCtx, Dispatch, Error, Handler, Message, Wrap};
use mpz_common::Context;
use std::future::Future;
use tls_backend::{Backend, BackendError, BackendNotify, DecryptMode, EncryptMode};
use tls_core::{
    cert::ServerCertDetails,
    ke::ServerKxDetails,
    key::PublicKey,
    msgs::{
        enums::ProtocolVersion,
        handshake::Random,
        message::{OpaqueMessage, PlainMessage},
    },
    suites::SupportedCipherSuite,
};
use tracing::{debug, Instrument};

#[derive(Clone)]
pub struct MpcTlsLeaderCtrl {
    address: Address<MpcTlsLeaderMsg>,
}

impl MpcTlsLeaderCtrl {
    /// Creates a new control for [`MpcTlsLeader`].
    pub fn new(address: Address<MpcTlsLeaderMsg>) -> Self {
        Self { address }
    }

    /// Defers decryption of any incoming messages.
    pub async fn defer_decryption(&self) -> Result<(), MpcTlsError> {
        self.address
            .send(DeferDecryption)
            .await
            .map_err(MpcTlsError::actor)?
    }

    /// Stops the leader actor.
    pub async fn stop(&self) -> Result<(), MpcTlsError> {
        self.address
            .queue(MpcTlsLeaderMsg::Stop(Stop))
            .await
            .map_err(MpcTlsError::actor)?;

        Ok(())
    }
}

impl std::fmt::Debug for MpcTlsLeaderCtrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcTlsLeaderCtrl").finish_non_exhaustive()
    }
}

impl MpcTlsLeader {
    /// Runs the leader actor.
    ///
    /// Returns a control handle and a future that resolves when the actor is
    /// stopped.
    ///
    /// # Note
    ///
    /// The future must be polled continuously to make progress.
    pub fn run(
        mut self,
    ) -> (
        MpcTlsLeaderCtrl,
        impl Future<Output = Result<(Context, LeaderOutput), MpcTlsError>>,
    ) {
        let (mut mailbox, address) = mailbox(100);

        let ctrl = MpcTlsLeaderCtrl::new(address);
        self.self_handle = Some(ctrl.clone());
        let fut = async move { ludi::run(&mut self, &mut mailbox).await };

        (ctrl, fut.in_current_span())
    }
}

impl Actor for MpcTlsLeader {
    type Stop = (Context, LeaderOutput);
    type Error = MpcTlsError;

    async fn stopped(&mut self) -> Result<Self::Stop, Self::Error> {
        debug!("leader actor stopped");

        let State::Closed { ctx, data, .. } = self.state.take() else {
            return Err(MpcTlsError::state("leader actor stopped in invalid state"));
        };

        Ok((ctx, data))
    }
}

impl Dispatch<MpcTlsLeader> for MpcTlsLeaderMsg {
    async fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut LudiCtx<MpcTlsLeader>,
        ret: R,
    ) {
        match self {
            MpcTlsLeaderMsg::BackendMsgSetProtocolVersion(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgSetProtocolVersion(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgSetCipherSuite(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgSetCipherSuite(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgGetSuite(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgGetSuite(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgSetEncrypt(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgSetEncrypt(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgSetDecrypt(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgSetDecrypt(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgGetClientRandom(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgGetClientRandom(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgGetClientKeyShare(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgGetClientKeyShare(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgSetServerRandom(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgSetServerRandom(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgSetServerKeyShare(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgSetServerKeyShare(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgSetServerCertDetails(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgSetServerCertDetails(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgSetServerKxDetails(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgSetServerKxDetails(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgSetHsHashClientKeyExchange(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgSetHsHashClientKeyExchange(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgSetHsHashServerHello(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgSetHsHashServerHello(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgGetServerFinishedVd(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgGetServerFinishedVd(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgGetClientFinishedVd(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgGetClientFinishedVd(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgPrepareEncryption(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgPrepareEncryption(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgNextIncoming(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgNextIncoming(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgPushIncoming(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgPushIncoming(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgNextOutgoing(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgNextOutgoing(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgPushOutgoing(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgPushOutgoing(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgFlush(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgFlush(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgGetNotify(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgGetNotify(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgIsEmpty(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgIsEmpty(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::BackendMsgServerClosed(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::BackendMsgServerClosed(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::DeferDecryption(msg) => {
                msg.dispatch(actor, ctx, |value| {
                    ret(Self::Return::DeferDecryption(value))
                })
                .await;
            }
            MpcTlsLeaderMsg::Stop(msg) => {
                msg.dispatch(actor, ctx, |value| ret(Self::Return::Stop(value)))
                    .await;
            }
        }
    }
}

#[async_trait]
impl Backend for MpcTlsLeaderCtrl {
    async fn set_protocol_version(&mut self, version: ProtocolVersion) -> Result<(), BackendError> {
        self.address
            .send(BackendMsgSetProtocolVersion { version })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn set_cipher_suite(&mut self, suite: SupportedCipherSuite) -> Result<(), BackendError> {
        self.address
            .send(BackendMsgSetCipherSuite { suite })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn get_suite(&mut self) -> Result<SupportedCipherSuite, BackendError> {
        self.address
            .send(BackendMsgGetSuite)
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn set_encrypt(&mut self, mode: EncryptMode) -> Result<(), BackendError> {
        self.address
            .send(BackendMsgSetEncrypt { mode })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn set_decrypt(&mut self, mode: DecryptMode) -> Result<(), BackendError> {
        self.address
            .send(BackendMsgSetDecrypt { mode })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn get_client_random(&mut self) -> Result<Random, BackendError> {
        self.address
            .send(BackendMsgGetClientRandom)
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn get_client_key_share(&mut self) -> Result<PublicKey, BackendError> {
        self.address
            .send(BackendMsgGetClientKeyShare)
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn set_server_random(&mut self, random: Random) -> Result<(), BackendError> {
        self.address
            .send(BackendMsgSetServerRandom { random })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn set_server_key_share(&mut self, key: PublicKey) -> Result<(), BackendError> {
        self.address
            .send(BackendMsgSetServerKeyShare { key })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn set_server_cert_details(
        &mut self,
        cert_details: ServerCertDetails,
    ) -> Result<(), BackendError> {
        self.address
            .send(BackendMsgSetServerCertDetails { cert_details })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn set_server_kx_details(
        &mut self,
        kx_details: ServerKxDetails,
    ) -> Result<(), BackendError> {
        self.address
            .send(BackendMsgSetServerKxDetails { kx_details })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn set_hs_hash_client_key_exchange(&mut self, hash: Vec<u8>) -> Result<(), BackendError> {
        self.address
            .send(BackendMsgSetHsHashClientKeyExchange { hash })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn set_hs_hash_server_hello(&mut self, hash: Vec<u8>) -> Result<(), BackendError> {
        self.address
            .send(BackendMsgSetHsHashServerHello { hash })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn get_server_finished_vd(&mut self, hash: Vec<u8>) -> Result<Vec<u8>, BackendError> {
        self.address
            .send(BackendMsgGetServerFinishedVd { hash })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn get_client_finished_vd(&mut self, hash: Vec<u8>) -> Result<Vec<u8>, BackendError> {
        self.address
            .send(BackendMsgGetClientFinishedVd { hash })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn prepare_encryption(&mut self) -> Result<(), BackendError> {
        self.address
            .send(BackendMsgPrepareEncryption)
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn push_incoming(&mut self, msg: OpaqueMessage) -> Result<(), BackendError> {
        self.address
            .send(BackendMsgPushIncoming { msg })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn next_incoming(&mut self) -> Result<Option<PlainMessage>, BackendError> {
        self.address
            .send(BackendMsgNextIncoming)
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn push_outgoing(&mut self, msg: PlainMessage) -> Result<(), BackendError> {
        self.address
            .send(BackendMsgPushOutgoing { msg })
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn next_outgoing(&mut self) -> Result<Option<OpaqueMessage>, BackendError> {
        self.address
            .send(BackendMsgNextOutgoing)
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn flush(&mut self) -> Result<(), BackendError> {
        self.address
            .send(BackendMsgFlush)
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn get_notify(&mut self) -> Result<BackendNotify, BackendError> {
        self.address
            .send(BackendMsgGetNotify)
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn is_empty(&mut self) -> Result<bool, BackendError> {
        self.address
            .send(BackendMsgIsEmpty)
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }

    async fn server_closed(&mut self) -> Result<(), BackendError> {
        self.address
            .send(BackendMsgServerClosed)
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?
    }
}

impl Dispatch<MpcTlsLeader> for BackendMsgSetProtocolVersion {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut LudiCtx<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<BackendMsgSetProtocolVersion> for MpcTlsLeader {
    async fn handle(
        &mut self,
        msg: BackendMsgSetProtocolVersion,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgSetProtocolVersion as Message>::Return {
        self.set_protocol_version(msg.version).await
    }
}

impl Dispatch<MpcTlsLeader> for BackendMsgSetCipherSuite {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut LudiCtx<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<BackendMsgSetCipherSuite> for MpcTlsLeader {
    async fn handle(
        &mut self,
        msg: BackendMsgSetCipherSuite,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgSetCipherSuite as Message>::Return {
        self.set_cipher_suite(msg.suite).await
    }
}

impl Dispatch<MpcTlsLeader> for BackendMsgGetSuite {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut LudiCtx<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<BackendMsgGetSuite> for MpcTlsLeader {
    async fn handle(
        &mut self,
        _msg: BackendMsgGetSuite,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgGetSuite as Message>::Return {
        self.get_suite().await
    }
}

impl Dispatch<MpcTlsLeader> for BackendMsgSetEncrypt {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut LudiCtx<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<BackendMsgSetEncrypt> for MpcTlsLeader {
    async fn handle(
        &mut self,
        msg: BackendMsgSetEncrypt,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgSetEncrypt as Message>::Return {
        self.set_encrypt(msg.mode).await
    }
}

impl Dispatch<MpcTlsLeader> for BackendMsgSetDecrypt {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut LudiCtx<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<BackendMsgSetDecrypt> for MpcTlsLeader {
    async fn handle(
        &mut self,
        msg: BackendMsgSetDecrypt,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgSetDecrypt as Message>::Return {
        self.set_decrypt(msg.mode).await
    }
}

impl Dispatch<MpcTlsLeader> for BackendMsgGetClientRandom {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut LudiCtx<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<BackendMsgGetClientRandom> for MpcTlsLeader {
    async fn handle(
        &mut self,
        _msg: BackendMsgGetClientRandom,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgGetClientRandom as Message>::Return {
        self.get_client_random().await
    }
}

impl Dispatch<MpcTlsLeader> for BackendMsgGetClientKeyShare {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut LudiCtx<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<BackendMsgGetClientKeyShare> for MpcTlsLeader {
    async fn handle(
        &mut self,
        _msg: BackendMsgGetClientKeyShare,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgGetClientKeyShare as Message>::Return {
        self.get_client_key_share().await
    }
}

impl Dispatch<MpcTlsLeader> for BackendMsgSetServerRandom {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut LudiCtx<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<BackendMsgSetServerRandom> for MpcTlsLeader {
    async fn handle(
        &mut self,
        msg: BackendMsgSetServerRandom,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgSetServerRandom as Message>::Return {
        self.set_server_random(msg.random).await
    }
}

impl Dispatch<MpcTlsLeader> for BackendMsgSetServerKeyShare {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut LudiCtx<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<BackendMsgSetServerKeyShare> for MpcTlsLeader {
    async fn handle(
        &mut self,
        msg: BackendMsgSetServerKeyShare,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgSetServerKeyShare as Message>::Return {
        self.set_server_key_share(msg.key).await
    }
}

impl Dispatch<MpcTlsLeader> for BackendMsgSetServerCertDetails {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut LudiCtx<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<BackendMsgSetServerCertDetails> for MpcTlsLeader {
    async fn handle(
        &mut self,
        msg: BackendMsgSetServerCertDetails,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgSetServerCertDetails as Message>::Return {
        self.set_server_cert_details(msg.cert_details).await
    }
}

impl Dispatch<MpcTlsLeader> for BackendMsgSetServerKxDetails {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut LudiCtx<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<BackendMsgSetServerKxDetails> for MpcTlsLeader {
    async fn handle(
        &mut self,
        msg: BackendMsgSetServerKxDetails,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgSetServerKxDetails as Message>::Return {
        self.set_server_kx_details(msg.kx_details).await
    }
}

impl Dispatch<MpcTlsLeader> for BackendMsgSetHsHashClientKeyExchange {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut LudiCtx<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<BackendMsgSetHsHashClientKeyExchange> for MpcTlsLeader {
    async fn handle(
        &mut self,
        msg: BackendMsgSetHsHashClientKeyExchange,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgSetHsHashClientKeyExchange as Message>::Return {
        self.set_hs_hash_client_key_exchange(msg.hash).await
    }
}

impl Dispatch<MpcTlsLeader> for BackendMsgSetHsHashServerHello {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut LudiCtx<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<BackendMsgSetHsHashServerHello> for MpcTlsLeader {
    async fn handle(
        &mut self,
        msg: BackendMsgSetHsHashServerHello,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgSetHsHashServerHello as Message>::Return {
        self.set_hs_hash_server_hello(msg.hash).await
    }
}

impl Dispatch<MpcTlsLeader> for BackendMsgGetServerFinishedVd {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut LudiCtx<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<BackendMsgGetServerFinishedVd> for MpcTlsLeader {
    async fn handle(
        &mut self,
        msg: BackendMsgGetServerFinishedVd,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgGetServerFinishedVd as Message>::Return {
        self.get_server_finished_vd(msg.hash).await
    }
}

impl Dispatch<MpcTlsLeader> for BackendMsgGetClientFinishedVd {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut LudiCtx<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<BackendMsgGetClientFinishedVd> for MpcTlsLeader {
    async fn handle(
        &mut self,
        msg: BackendMsgGetClientFinishedVd,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgGetClientFinishedVd as Message>::Return {
        self.get_client_finished_vd(msg.hash).await
    }
}

impl Dispatch<MpcTlsLeader> for BackendMsgPrepareEncryption {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut LudiCtx<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<BackendMsgPrepareEncryption> for MpcTlsLeader {
    async fn handle(
        &mut self,
        _msg: BackendMsgPrepareEncryption,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgPrepareEncryption as Message>::Return {
        self.prepare_encryption().await
    }
}

impl Dispatch<MpcTlsLeader> for BackendMsgPushIncoming {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut LudiCtx<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<BackendMsgPushIncoming> for MpcTlsLeader {
    async fn handle(
        &mut self,
        msg: BackendMsgPushIncoming,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgPushIncoming as Message>::Return {
        self.push_incoming(msg.msg).await
    }
}

impl Dispatch<MpcTlsLeader> for BackendMsgNextIncoming {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut LudiCtx<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<BackendMsgNextIncoming> for MpcTlsLeader {
    async fn handle(
        &mut self,
        _msg: BackendMsgNextIncoming,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgNextIncoming as Message>::Return {
        self.next_incoming().await
    }
}

impl Dispatch<MpcTlsLeader> for BackendMsgPushOutgoing {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut LudiCtx<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<BackendMsgPushOutgoing> for MpcTlsLeader {
    async fn handle(
        &mut self,
        msg: BackendMsgPushOutgoing,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgPushOutgoing as Message>::Return {
        self.push_outgoing(msg.msg).await
    }
}

impl Dispatch<MpcTlsLeader> for BackendMsgNextOutgoing {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut LudiCtx<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<BackendMsgNextOutgoing> for MpcTlsLeader {
    async fn handle(
        &mut self,
        _msg: BackendMsgNextOutgoing,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgNextOutgoing as Message>::Return {
        self.next_outgoing().await
    }
}

impl Dispatch<MpcTlsLeader> for BackendMsgFlush {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut LudiCtx<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<BackendMsgFlush> for MpcTlsLeader {
    async fn handle(
        &mut self,
        _msg: BackendMsgFlush,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgFlush as Message>::Return {
        self.flush().await
    }
}

impl Dispatch<MpcTlsLeader> for BackendMsgGetNotify {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut LudiCtx<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<BackendMsgGetNotify> for MpcTlsLeader {
    async fn handle(
        &mut self,
        _msg: BackendMsgGetNotify,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgGetNotify as Message>::Return {
        self.get_notify().await
    }
}

impl Dispatch<MpcTlsLeader> for BackendMsgIsEmpty {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut LudiCtx<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<BackendMsgIsEmpty> for MpcTlsLeader {
    async fn handle(
        &mut self,
        _msg: BackendMsgIsEmpty,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgIsEmpty as Message>::Return {
        self.is_empty().await
    }
}

impl Dispatch<MpcTlsLeader> for BackendMsgServerClosed {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut LudiCtx<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<BackendMsgServerClosed> for MpcTlsLeader {
    async fn handle(
        &mut self,
        _msg: BackendMsgServerClosed,
        _ctx: &mut LudiCtx<Self>,
    ) -> <BackendMsgServerClosed as Message>::Return {
        self.server_closed().await
    }
}

impl Dispatch<MpcTlsLeader> for DeferDecryption {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut LudiCtx<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<DeferDecryption> for MpcTlsLeader {
    async fn handle(
        &mut self,
        _msg: DeferDecryption,
        _ctx: &mut LudiCtx<Self>,
    ) -> <DeferDecryption as Message>::Return {
        self.defer_decryption().await
    }
}

impl Dispatch<MpcTlsLeader> for Stop {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsLeader,
        ctx: &mut LudiCtx<MpcTlsLeader>,
        ret: R,
    ) -> impl Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<Stop> for MpcTlsLeader {
    async fn handle(&mut self, _msg: Stop, ctx: &mut LudiCtx<Self>) -> <Stop as Message>::Return {
        self.stop(ctx);

        Ok(())
    }
}

#[allow(missing_docs)]
pub enum MpcTlsLeaderMsg {
    BackendMsgSetProtocolVersion(BackendMsgSetProtocolVersion),
    BackendMsgSetCipherSuite(BackendMsgSetCipherSuite),
    BackendMsgGetSuite(BackendMsgGetSuite),
    BackendMsgSetEncrypt(BackendMsgSetEncrypt),
    BackendMsgSetDecrypt(BackendMsgSetDecrypt),
    BackendMsgGetClientRandom(BackendMsgGetClientRandom),
    BackendMsgGetClientKeyShare(BackendMsgGetClientKeyShare),
    BackendMsgSetServerRandom(BackendMsgSetServerRandom),
    BackendMsgSetServerKeyShare(BackendMsgSetServerKeyShare),
    BackendMsgSetServerCertDetails(BackendMsgSetServerCertDetails),
    BackendMsgSetServerKxDetails(BackendMsgSetServerKxDetails),
    BackendMsgSetHsHashClientKeyExchange(BackendMsgSetHsHashClientKeyExchange),
    BackendMsgSetHsHashServerHello(BackendMsgSetHsHashServerHello),
    BackendMsgGetServerFinishedVd(BackendMsgGetServerFinishedVd),
    BackendMsgGetClientFinishedVd(BackendMsgGetClientFinishedVd),
    BackendMsgPrepareEncryption(BackendMsgPrepareEncryption),
    BackendMsgNextIncoming(BackendMsgNextIncoming),
    BackendMsgPushIncoming(BackendMsgPushIncoming),
    BackendMsgNextOutgoing(BackendMsgNextOutgoing),
    BackendMsgPushOutgoing(BackendMsgPushOutgoing),
    BackendMsgFlush(BackendMsgFlush),
    BackendMsgGetNotify(BackendMsgGetNotify),
    BackendMsgIsEmpty(BackendMsgIsEmpty),
    BackendMsgServerClosed(BackendMsgServerClosed),
    DeferDecryption(DeferDecryption),
    Stop(Stop),
}

impl Message for MpcTlsLeaderMsg {
    type Return = MpcTlsLeaderMsgReturn;
}

#[allow(missing_docs)]
pub enum MpcTlsLeaderMsgReturn {
    BackendMsgSetProtocolVersion(<BackendMsgSetProtocolVersion as Message>::Return),
    BackendMsgSetCipherSuite(<BackendMsgSetCipherSuite as Message>::Return),
    BackendMsgGetSuite(<BackendMsgGetSuite as Message>::Return),
    BackendMsgSetEncrypt(<BackendMsgSetEncrypt as Message>::Return),
    BackendMsgSetDecrypt(<BackendMsgSetDecrypt as Message>::Return),
    BackendMsgGetClientRandom(<BackendMsgGetClientRandom as Message>::Return),
    BackendMsgGetClientKeyShare(<BackendMsgGetClientKeyShare as Message>::Return),
    BackendMsgSetServerRandom(<BackendMsgSetServerRandom as Message>::Return),
    BackendMsgSetServerKeyShare(<BackendMsgSetServerKeyShare as Message>::Return),
    BackendMsgSetServerCertDetails(<BackendMsgSetServerCertDetails as Message>::Return),
    BackendMsgSetServerKxDetails(<BackendMsgSetServerKxDetails as Message>::Return),
    BackendMsgSetHsHashClientKeyExchange(<BackendMsgSetHsHashClientKeyExchange as Message>::Return),
    BackendMsgSetHsHashServerHello(<BackendMsgSetHsHashServerHello as Message>::Return),
    BackendMsgGetServerFinishedVd(<BackendMsgGetServerFinishedVd as Message>::Return),
    BackendMsgGetClientFinishedVd(<BackendMsgGetClientFinishedVd as Message>::Return),
    BackendMsgPrepareEncryption(<BackendMsgPrepareEncryption as Message>::Return),
    BackendMsgNextIncoming(<BackendMsgNextIncoming as Message>::Return),
    BackendMsgPushIncoming(<BackendMsgPushIncoming as Message>::Return),
    BackendMsgNextOutgoing(<BackendMsgNextOutgoing as Message>::Return),
    BackendMsgPushOutgoing(<BackendMsgPushOutgoing as Message>::Return),
    BackendMsgFlush(<BackendMsgFlush as Message>::Return),
    BackendMsgGetNotify(<BackendMsgGetNotify as Message>::Return),
    BackendMsgIsEmpty(<BackendMsgIsEmpty as Message>::Return),
    BackendMsgServerClosed(<BackendMsgServerClosed as Message>::Return),
    DeferDecryption(<DeferDecryption as Message>::Return),
    Stop(<Stop as Message>::Return),
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetProtocolVersion {
    pub version: ProtocolVersion,
}

impl Message for BackendMsgSetProtocolVersion {
    type Return = Result<(), BackendError>;
}

impl From<BackendMsgSetProtocolVersion> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgSetProtocolVersion) -> Self {
        MpcTlsLeaderMsg::BackendMsgSetProtocolVersion(value)
    }
}

impl Wrap<BackendMsgSetProtocolVersion> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgSetProtocolVersion as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgSetProtocolVersion(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetCipherSuite {
    pub suite: SupportedCipherSuite,
}

impl Message for BackendMsgSetCipherSuite {
    type Return = Result<(), BackendError>;
}

impl From<BackendMsgSetCipherSuite> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgSetCipherSuite) -> Self {
        MpcTlsLeaderMsg::BackendMsgSetCipherSuite(value)
    }
}

impl Wrap<BackendMsgSetCipherSuite> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgSetCipherSuite as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgSetCipherSuite(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgGetSuite;

impl Message for BackendMsgGetSuite {
    type Return = Result<SupportedCipherSuite, BackendError>;
}

impl From<BackendMsgGetSuite> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgGetSuite) -> Self {
        MpcTlsLeaderMsg::BackendMsgGetSuite(value)
    }
}

impl Wrap<BackendMsgGetSuite> for MpcTlsLeaderMsg {
    fn unwrap_return(ret: Self::Return) -> Result<<BackendMsgGetSuite as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgGetSuite(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetEncrypt {
    pub mode: EncryptMode,
}

impl Message for BackendMsgSetEncrypt {
    type Return = Result<(), BackendError>;
}

impl From<BackendMsgSetEncrypt> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgSetEncrypt) -> Self {
        MpcTlsLeaderMsg::BackendMsgSetEncrypt(value)
    }
}

impl Wrap<BackendMsgSetEncrypt> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgSetEncrypt as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgSetEncrypt(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetDecrypt {
    pub mode: DecryptMode,
}

impl Message for BackendMsgSetDecrypt {
    type Return = Result<(), BackendError>;
}

impl From<BackendMsgSetDecrypt> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgSetDecrypt) -> Self {
        MpcTlsLeaderMsg::BackendMsgSetDecrypt(value)
    }
}

impl Wrap<BackendMsgSetDecrypt> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgSetDecrypt as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgSetDecrypt(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgGetClientRandom;

impl Message for BackendMsgGetClientRandom {
    type Return = Result<Random, BackendError>;
}

impl From<BackendMsgGetClientRandom> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgGetClientRandom) -> Self {
        MpcTlsLeaderMsg::BackendMsgGetClientRandom(value)
    }
}

impl Wrap<BackendMsgGetClientRandom> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgGetClientRandom as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgGetClientRandom(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgGetClientKeyShare;

impl Message for BackendMsgGetClientKeyShare {
    type Return = Result<PublicKey, BackendError>;
}

impl From<BackendMsgGetClientKeyShare> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgGetClientKeyShare) -> Self {
        MpcTlsLeaderMsg::BackendMsgGetClientKeyShare(value)
    }
}

impl Wrap<BackendMsgGetClientKeyShare> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgGetClientKeyShare as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgGetClientKeyShare(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetServerRandom {
    pub random: Random,
}

impl Message for BackendMsgSetServerRandom {
    type Return = Result<(), BackendError>;
}

impl From<BackendMsgSetServerRandom> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgSetServerRandom) -> Self {
        MpcTlsLeaderMsg::BackendMsgSetServerRandom(value)
    }
}

impl Wrap<BackendMsgSetServerRandom> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgSetServerRandom as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgSetServerRandom(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetServerKeyShare {
    pub key: PublicKey,
}

impl Message for BackendMsgSetServerKeyShare {
    type Return = Result<(), BackendError>;
}

impl From<BackendMsgSetServerKeyShare> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgSetServerKeyShare) -> Self {
        MpcTlsLeaderMsg::BackendMsgSetServerKeyShare(value)
    }
}

impl Wrap<BackendMsgSetServerKeyShare> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgSetServerKeyShare as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgSetServerKeyShare(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetServerCertDetails {
    pub cert_details: ServerCertDetails,
}

impl Message for BackendMsgSetServerCertDetails {
    type Return = Result<(), BackendError>;
}

impl From<BackendMsgSetServerCertDetails> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgSetServerCertDetails) -> Self {
        MpcTlsLeaderMsg::BackendMsgSetServerCertDetails(value)
    }
}

impl Wrap<BackendMsgSetServerCertDetails> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgSetServerCertDetails as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgSetServerCertDetails(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetServerKxDetails {
    pub kx_details: ServerKxDetails,
}

impl Message for BackendMsgSetServerKxDetails {
    type Return = Result<(), BackendError>;
}

impl From<BackendMsgSetServerKxDetails> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgSetServerKxDetails) -> Self {
        MpcTlsLeaderMsg::BackendMsgSetServerKxDetails(value)
    }
}

impl Wrap<BackendMsgSetServerKxDetails> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgSetServerKxDetails as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgSetServerKxDetails(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetHsHashClientKeyExchange {
    pub hash: Vec<u8>,
}

impl Message for BackendMsgSetHsHashClientKeyExchange {
    type Return = Result<(), BackendError>;
}

impl From<BackendMsgSetHsHashClientKeyExchange> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgSetHsHashClientKeyExchange) -> Self {
        MpcTlsLeaderMsg::BackendMsgSetHsHashClientKeyExchange(value)
    }
}

impl Wrap<BackendMsgSetHsHashClientKeyExchange> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgSetHsHashClientKeyExchange as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgSetHsHashClientKeyExchange(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgSetHsHashServerHello {
    pub hash: Vec<u8>,
}

impl Message for BackendMsgSetHsHashServerHello {
    type Return = Result<(), BackendError>;
}

impl From<BackendMsgSetHsHashServerHello> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgSetHsHashServerHello) -> Self {
        MpcTlsLeaderMsg::BackendMsgSetHsHashServerHello(value)
    }
}

impl Wrap<BackendMsgSetHsHashServerHello> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgSetHsHashServerHello as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgSetHsHashServerHello(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgGetServerFinishedVd {
    pub hash: Vec<u8>,
}

impl Message for BackendMsgGetServerFinishedVd {
    type Return = Result<Vec<u8>, BackendError>;
}

impl From<BackendMsgGetServerFinishedVd> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgGetServerFinishedVd) -> Self {
        MpcTlsLeaderMsg::BackendMsgGetServerFinishedVd(value)
    }
}

impl Wrap<BackendMsgGetServerFinishedVd> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgGetServerFinishedVd as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgGetServerFinishedVd(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgGetClientFinishedVd {
    pub hash: Vec<u8>,
}

impl Message for BackendMsgGetClientFinishedVd {
    type Return = Result<Vec<u8>, BackendError>;
}

impl From<BackendMsgGetClientFinishedVd> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgGetClientFinishedVd) -> Self {
        MpcTlsLeaderMsg::BackendMsgGetClientFinishedVd(value)
    }
}

impl Wrap<BackendMsgGetClientFinishedVd> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgGetClientFinishedVd as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgGetClientFinishedVd(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgPrepareEncryption;

impl Message for BackendMsgPrepareEncryption {
    type Return = Result<(), BackendError>;
}

impl From<BackendMsgPrepareEncryption> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgPrepareEncryption) -> Self {
        MpcTlsLeaderMsg::BackendMsgPrepareEncryption(value)
    }
}

impl Wrap<BackendMsgPrepareEncryption> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgPrepareEncryption as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgPrepareEncryption(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgPushIncoming {
    pub msg: OpaqueMessage,
}

impl Message for BackendMsgPushIncoming {
    type Return = Result<(), BackendError>;
}

impl From<BackendMsgPushIncoming> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgPushIncoming) -> Self {
        MpcTlsLeaderMsg::BackendMsgPushIncoming(value)
    }
}

impl Wrap<BackendMsgPushIncoming> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgPushIncoming as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgPushIncoming(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgNextIncoming;

impl Message for BackendMsgNextIncoming {
    type Return = Result<Option<PlainMessage>, BackendError>;
}

impl From<BackendMsgNextIncoming> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgNextIncoming) -> Self {
        MpcTlsLeaderMsg::BackendMsgNextIncoming(value)
    }
}

impl Wrap<BackendMsgNextIncoming> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgNextIncoming as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgNextIncoming(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgPushOutgoing {
    pub msg: PlainMessage,
}

impl Message for BackendMsgPushOutgoing {
    type Return = Result<(), BackendError>;
}

impl From<BackendMsgPushOutgoing> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgPushOutgoing) -> Self {
        MpcTlsLeaderMsg::BackendMsgPushOutgoing(value)
    }
}

impl Wrap<BackendMsgPushOutgoing> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgPushOutgoing as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgPushOutgoing(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgNextOutgoing;

impl Message for BackendMsgNextOutgoing {
    type Return = Result<Option<OpaqueMessage>, BackendError>;
}

impl From<BackendMsgNextOutgoing> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgNextOutgoing) -> Self {
        MpcTlsLeaderMsg::BackendMsgNextOutgoing(value)
    }
}

impl Wrap<BackendMsgNextOutgoing> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgNextOutgoing as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgNextOutgoing(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgFlush;

impl Message for BackendMsgFlush {
    type Return = Result<(), BackendError>;
}

impl From<BackendMsgFlush> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgFlush) -> Self {
        MpcTlsLeaderMsg::BackendMsgFlush(value)
    }
}

impl Wrap<BackendMsgFlush> for MpcTlsLeaderMsg {
    fn unwrap_return(ret: Self::Return) -> Result<<BackendMsgFlush as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgFlush(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgGetNotify;

impl Message for BackendMsgGetNotify {
    type Return = Result<BackendNotify, BackendError>;
}

impl From<BackendMsgGetNotify> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgGetNotify) -> Self {
        MpcTlsLeaderMsg::BackendMsgGetNotify(value)
    }
}

impl Wrap<BackendMsgGetNotify> for MpcTlsLeaderMsg {
    fn unwrap_return(ret: Self::Return) -> Result<<BackendMsgGetNotify as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgGetNotify(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgIsEmpty;

impl Message for BackendMsgIsEmpty {
    type Return = Result<bool, BackendError>;
}

impl From<BackendMsgIsEmpty> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgIsEmpty) -> Self {
        MpcTlsLeaderMsg::BackendMsgIsEmpty(value)
    }
}

impl Wrap<BackendMsgIsEmpty> for MpcTlsLeaderMsg {
    fn unwrap_return(ret: Self::Return) -> Result<<BackendMsgIsEmpty as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgIsEmpty(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub struct BackendMsgServerClosed;

impl Message for BackendMsgServerClosed {
    type Return = Result<(), BackendError>;
}

impl From<BackendMsgServerClosed> for MpcTlsLeaderMsg {
    fn from(value: BackendMsgServerClosed) -> Self {
        MpcTlsLeaderMsg::BackendMsgServerClosed(value)
    }
}

impl Wrap<BackendMsgServerClosed> for MpcTlsLeaderMsg {
    fn unwrap_return(
        ret: Self::Return,
    ) -> Result<<BackendMsgServerClosed as Message>::Return, Error> {
        match ret {
            Self::Return::BackendMsgServerClosed(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

/// Message to start deferring the decryption
#[allow(missing_docs)]
#[derive(Debug)]
pub struct DeferDecryption;

impl Message for DeferDecryption {
    type Return = Result<(), MpcTlsError>;
}

impl From<DeferDecryption> for MpcTlsLeaderMsg {
    fn from(value: DeferDecryption) -> Self {
        MpcTlsLeaderMsg::DeferDecryption(value)
    }
}

impl Wrap<DeferDecryption> for MpcTlsLeaderMsg {
    fn unwrap_return(ret: Self::Return) -> Result<<DeferDecryption as Message>::Return, Error> {
        match ret {
            Self::Return::DeferDecryption(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}

#[derive(Debug)]
pub struct Stop;

impl Message for Stop {
    type Return = Result<(), MpcTlsError>;
}

impl From<Stop> for MpcTlsLeaderMsg {
    fn from(value: Stop) -> Self {
        MpcTlsLeaderMsg::Stop(value)
    }
}

impl Wrap<Stop> for MpcTlsLeaderMsg {
    fn unwrap_return(ret: Self::Return) -> Result<<Stop as Message>::Return, Error> {
        match ret {
            Self::Return::Stop(value) => Ok(value),
            _ => Err(Error::Wrapper),
        }
    }
}
