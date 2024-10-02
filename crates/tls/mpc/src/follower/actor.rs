use crate::{
    follower::{Closed, MpcTlsFollower, MpcTlsFollowerData},
    msg::{
        mpc_tls_follower_msg::MpcTlsFollowerMsg, ClientFinishedVd, CloseConnection, Commit,
        CommitMessage, ComputeKeyExchange, DecryptAlert, DecryptMessage, DecryptServerFinished,
        EncryptAlert, EncryptClientFinished, EncryptMessage, ServerFinishedVd,
    },
    MpcTlsError,
};
use futures::{FutureExt, StreamExt};
use ludi::{Address, Dispatch, Handler, Message};
use std::future::Future;
use tracing::{debug, Instrument};

#[derive(Clone)]
pub struct MpcTlsFollowerCtrl {
    address: Address<MpcTlsFollowerMsg>,
}

impl MpcTlsFollowerCtrl {
    /// Creates a new control for [`MpcTlsLeader`].
    pub fn new(address: Address<MpcTlsFollowerMsg>) -> Self {
        Self { address }
    }
}

impl ludi::Actor for MpcTlsFollower {
    type Stop = MpcTlsFollowerData;
    type Error = MpcTlsError;

    async fn stopped(&mut self) -> Result<Self::Stop, Self::Error> {
        debug!("follower actor stopped");

        let Closed { server_key } = self.state.take().try_into_closed()?;

        let bytes_sent = self.encrypter.sent_bytes();
        let bytes_recv = self.decrypter.recv_bytes();

        Ok(MpcTlsFollowerData {
            server_key,
            bytes_sent,
            bytes_recv,
        })
    }
}

impl MpcTlsFollower {
    /// Runs the follower actor.
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
        MpcTlsFollowerCtrl,
        impl Future<Output = Result<MpcTlsFollowerData, MpcTlsError>>,
    ) {
        let (mut mailbox, addr) = ludi::mailbox::<MpcTlsFollowerMsg>(100);
        let ctrl = MpcTlsFollowerCtrl::new(addr);
        let ctrl_fut = ctrl.clone();

        let mut stream = self
            .stream
            .take()
            .expect("stream should be present from constructor");

        let mut remote_fut = Box::pin(async move {
            while let Some(msg) = stream.next().await {
                let msg = MpcTlsFollowerMsg::try_from(msg?)?;
                ctrl_fut.address.send(msg).await?;
            }

            Ok::<_, MpcTlsError>(())
        })
        .fuse();

        let mut actor_fut =
            Box::pin(async move { ludi::run(&mut self, &mut mailbox).await }).fuse();

        let fut = async move {
            loop {
                futures::select! {
                    res = &mut remote_fut => {
                        res?;
                    },
                    res = &mut actor_fut => return res,
                }
            }
        };

        (ctrl, fut.in_current_span())
    }
}

impl Dispatch<MpcTlsFollower> for ComputeKeyExchange {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsFollower,
        ctx: &mut ludi::Context<MpcTlsFollower>,
        ret: R,
    ) -> impl std::future::Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<ComputeKeyExchange> for MpcTlsFollower {
    fn handle(
        &mut self,
        msg: ComputeKeyExchange,
        ctx: &mut ludi::Context<Self>,
    ) -> impl std::future::Future<Output = <ComputeKeyExchange as Message>::Return> + Send {
        let ComputeKeyExchange { server_random } = msg;

        async move {
            ctx.try_or_stop(|_| self.compute_key_exchange(server_random))
                .await
        }
    }
}

impl Dispatch<MpcTlsFollower> for ClientFinishedVd {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsFollower,
        ctx: &mut ludi::Context<MpcTlsFollower>,
        ret: R,
    ) -> impl std::future::Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<ClientFinishedVd> for MpcTlsFollower {
    async fn handle(
        &mut self,
        msg: ClientFinishedVd,
        ctx: &mut ludi::Context<Self>,
    ) -> <ClientFinishedVd as Message>::Return {
        ctx.try_or_stop(|_| self.client_finished_vd(msg.handshake_hash))
            .await
    }
}

impl Dispatch<MpcTlsFollower> for ServerFinishedVd {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsFollower,
        ctx: &mut ludi::Context<MpcTlsFollower>,
        ret: R,
    ) -> impl std::future::Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<ServerFinishedVd> for MpcTlsFollower {
    async fn handle(
        &mut self,
        msg: ServerFinishedVd,
        ctx: &mut ludi::Context<Self>,
    ) -> <ServerFinishedVd as Message>::Return {
        ctx.try_or_stop(|_| self.server_finished_vd(msg.handshake_hash))
            .await
    }
}

impl Dispatch<MpcTlsFollower> for EncryptClientFinished {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsFollower,
        ctx: &mut ludi::Context<MpcTlsFollower>,
        ret: R,
    ) -> impl std::future::Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<EncryptClientFinished> for MpcTlsFollower {
    async fn handle(
        &mut self,
        _msg: EncryptClientFinished,
        ctx: &mut ludi::Context<Self>,
    ) -> <EncryptClientFinished as Message>::Return {
        ctx.try_or_stop(|_| self.encrypt_client_finished()).await
    }
}

impl Dispatch<MpcTlsFollower> for EncryptAlert {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsFollower,
        ctx: &mut ludi::Context<MpcTlsFollower>,
        ret: R,
    ) -> impl std::future::Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<EncryptAlert> for MpcTlsFollower {
    async fn handle(
        &mut self,
        msg: EncryptAlert,
        ctx: &mut ludi::Context<Self>,
    ) -> <EncryptAlert as Message>::Return {
        ctx.try_or_stop(|_| self.encrypt_alert(msg.msg)).await
    }
}

impl Dispatch<MpcTlsFollower> for EncryptMessage {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsFollower,
        ctx: &mut ludi::Context<MpcTlsFollower>,
        ret: R,
    ) -> impl std::future::Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<EncryptMessage> for MpcTlsFollower {
    async fn handle(
        &mut self,
        msg: EncryptMessage,
        ctx: &mut ludi::Context<Self>,
    ) -> <EncryptMessage as Message>::Return {
        ctx.try_or_stop(|_| self.encrypt_message(msg.len)).await
    }
}

impl Dispatch<MpcTlsFollower> for DecryptServerFinished {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsFollower,
        ctx: &mut ludi::Context<MpcTlsFollower>,
        ret: R,
    ) -> impl std::future::Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<DecryptServerFinished> for MpcTlsFollower {
    async fn handle(
        &mut self,
        msg: DecryptServerFinished,
        ctx: &mut ludi::Context<Self>,
    ) -> <DecryptServerFinished as Message>::Return {
        ctx.try_or_stop(|_| self.decrypt_server_finished(msg.ciphertext))
            .await
    }
}

impl Dispatch<MpcTlsFollower> for DecryptAlert {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsFollower,
        ctx: &mut ludi::Context<MpcTlsFollower>,
        ret: R,
    ) -> impl std::future::Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<DecryptAlert> for MpcTlsFollower {
    async fn handle(
        &mut self,
        msg: DecryptAlert,
        ctx: &mut ludi::Context<Self>,
    ) -> <DecryptAlert as Message>::Return {
        ctx.try_or_stop(|_| self.decrypt_alert(msg.ciphertext))
            .await
    }
}

impl Dispatch<MpcTlsFollower> for CommitMessage {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsFollower,
        ctx: &mut ludi::Context<MpcTlsFollower>,
        ret: R,
    ) -> impl std::future::Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<CommitMessage> for MpcTlsFollower {
    async fn handle(
        &mut self,
        msg: CommitMessage,
        ctx: &mut ludi::Context<Self>,
    ) -> <CommitMessage as Message>::Return {
        ctx.try_or_stop(|_| async { self.commit_message(msg.msg) })
            .await;
    }
}

impl Dispatch<MpcTlsFollower> for DecryptMessage {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsFollower,
        ctx: &mut ludi::Context<MpcTlsFollower>,
        ret: R,
    ) -> impl std::future::Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<DecryptMessage> for MpcTlsFollower {
    async fn handle(
        &mut self,
        _msg: DecryptMessage,
        ctx: &mut ludi::Context<Self>,
    ) -> <DecryptMessage as Message>::Return {
        ctx.try_or_stop(|_| self.decrypt_message()).await
    }
}

impl Dispatch<MpcTlsFollower> for CloseConnection {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsFollower,
        ctx: &mut ludi::Context<MpcTlsFollower>,
        ret: R,
    ) -> impl std::future::Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<CloseConnection> for MpcTlsFollower {
    async fn handle(
        &mut self,
        _msg: CloseConnection,
        ctx: &mut ludi::Context<Self>,
    ) -> <CloseConnection as Message>::Return {
        ctx.try_or_stop(|_| async { self.close_connection() }).await;
        ctx.stop();
        Some(())
    }
}

impl Dispatch<MpcTlsFollower> for Commit {
    fn dispatch<R: FnOnce(Self::Return) + Send>(
        self,
        actor: &mut MpcTlsFollower,
        ctx: &mut ludi::Context<MpcTlsFollower>,
        ret: R,
    ) -> impl std::future::Future<Output = ()> + Send {
        actor.process(self, ctx, ret)
    }
}

impl Handler<Commit> for MpcTlsFollower {
    async fn handle(
        &mut self,
        _msg: Commit,
        ctx: &mut ludi::Context<Self>,
    ) -> <Commit as Message>::Return {
        ctx.try_or_stop(|_| async { self.commit().await }).await
    }
}
