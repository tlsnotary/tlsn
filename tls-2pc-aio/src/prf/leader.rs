use super::{circuits, PRFChannel, PRFError};
use futures::{SinkExt, StreamExt};
use mpc_aio::protocol::{garble::Execute, point_addition::P256SecretShare};
use tls_2pc_core::{
    prf::{self as core, leader_state as state, PRFMessage},
    SessionKeyShares,
};

pub struct MasterSecret {
    core: core::PRFLeader<state::Ms1>,
}

pub struct ClientFinished {
    core: core::PRFLeader<state::Cf1>,
}

pub struct ServerFinished {
    core: core::PRFLeader<state::Sf1>,
}

pub struct PRFLeader<G, S>
where
    G: Execute + Send,
{
    state: S,
    channel: PRFChannel,
    gc_exec: G,
}

impl<G> PRFLeader<G, MasterSecret>
where
    G: Execute + Send,
{
    pub fn new(channel: PRFChannel, gc_exec: G) -> PRFLeader<G, MasterSecret> {
        PRFLeader {
            state: MasterSecret {
                core: core::PRFLeader::new(),
            },
            channel,
            gc_exec,
        }
    }

    /// Computes leader's shares of the TLS session keys using the session randoms and their
    /// share of the PMS
    ///
    /// Returns session key shares
    pub async fn compute_session_keys(
        mut self,
        client_random: [u8; 32],
        server_random: [u8; 32],
        secret_share: P256SecretShare,
    ) -> Result<(SessionKeyShares, PRFLeader<G, ClientFinished>), PRFError> {
        let inner_hash_state = circuits::leader_c1(&mut self.gc_exec, secret_share).await?;
        let (msg, core) = self
            .state
            .core
            .next(client_random, server_random, inner_hash_state);

        self.channel.send(PRFMessage::LeaderMs1(msg)).await?;

        let msg = match self.channel.next().await {
            Some(PRFMessage::FollowerMs1(msg)) => msg,
            Some(m) => return Err(PRFError::UnexpectedMessage(m)),
            None => {
                return Err(PRFError::from(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "stream closed unexpectedly",
                )))
            }
        };

        let (msg, core) = core.next(msg);
        self.channel.send(PRFMessage::LeaderMs2(msg)).await?;

        let msg = match self.channel.next().await {
            Some(PRFMessage::FollowerMs2(msg)) => msg,
            Some(m) => return Err(PRFError::UnexpectedMessage(m)),
            None => {
                return Err(PRFError::from(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "stream closed unexpectedly",
                )))
            }
        };

        let (msg, core) = core.next(msg);
        self.channel.send(PRFMessage::LeaderMs3(msg)).await?;

        let p1_inner_hash = core.p1_inner_hash();
        let inner_hash_state = circuits::leader_c2(&mut self.gc_exec, p1_inner_hash).await?;

        let (msg, core) = core.next().next(inner_hash_state);
        self.channel.send(PRFMessage::LeaderKe1(msg)).await?;

        let msg = match self.channel.next().await {
            Some(PRFMessage::FollowerKe1(msg)) => msg,
            Some(m) => return Err(PRFError::UnexpectedMessage(m)),
            None => {
                return Err(PRFError::from(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "stream closed unexpectedly",
                )))
            }
        };

        let (msg, core) = core.next(msg);
        self.channel.send(PRFMessage::LeaderKe2(msg)).await?;

        let msg = match self.channel.next().await {
            Some(PRFMessage::FollowerKe2(msg)) => msg,
            Some(m) => return Err(PRFError::UnexpectedMessage(m)),
            None => {
                return Err(PRFError::from(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "stream closed unexpectedly",
                )))
            }
        };

        let core = core.next(msg);
        let p1_inner_hash = core.p1_inner_hash();
        let p2_inner_hash = core.p2_inner_hash();

        let session_keys =
            circuits::leader_c3(&mut self.gc_exec, p1_inner_hash, p2_inner_hash).await?;

        Ok((
            session_keys,
            PRFLeader {
                state: ClientFinished { core: core.next() },
                channel: self.channel,
                gc_exec: self.gc_exec,
            },
        ))
    }
}

impl<G> PRFLeader<G, ClientFinished>
where
    G: Execute + Send,
{
    /// Computes client finished data using handshake hash
    ///
    /// Returns client finished data and next state
    pub async fn compute_client_finished(
        mut self,
        hash: &[u8],
    ) -> Result<([u8; 12], PRFLeader<G, ServerFinished>), PRFError> {
        let (msg, core) = self.state.core.next(hash);
        self.channel.send(PRFMessage::LeaderCf1(msg)).await?;

        let msg = match self.channel.next().await {
            Some(PRFMessage::FollowerCf1(msg)) => msg,
            Some(m) => return Err(PRFError::UnexpectedMessage(m)),
            None => {
                return Err(PRFError::from(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "stream closed unexpectedly",
                )))
            }
        };

        let (msg, core) = core.next(msg);
        self.channel.send(PRFMessage::LeaderCf2(msg)).await?;

        let msg = match self.channel.next().await {
            Some(PRFMessage::FollowerCf2(msg)) => msg,
            Some(m) => return Err(PRFError::UnexpectedMessage(m)),
            None => {
                return Err(PRFError::from(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "stream closed unexpectedly",
                )))
            }
        };

        let (vd, core) = core.next(msg);

        Ok((
            vd,
            PRFLeader {
                state: ServerFinished { core },
                channel: self.channel,
                gc_exec: self.gc_exec,
            },
        ))
    }
}

impl<G> PRFLeader<G, ServerFinished>
where
    G: Execute + Send,
{
    /// Computes server finished data using handshake hash
    ///
    /// Returns server finished data
    pub async fn compute_server_finished(mut self, hash: &[u8]) -> Result<[u8; 12], PRFError> {
        let (msg, core) = self.state.core.next(hash);
        self.channel.send(PRFMessage::LeaderSf1(msg)).await?;

        let msg = match self.channel.next().await {
            Some(PRFMessage::FollowerSf1(msg)) => msg,
            Some(m) => return Err(PRFError::UnexpectedMessage(m)),
            None => {
                return Err(PRFError::from(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "stream closed unexpectedly",
                )))
            }
        };

        let (msg, core) = core.next(msg);
        self.channel.send(PRFMessage::LeaderSf2(msg)).await?;

        let msg = match self.channel.next().await {
            Some(PRFMessage::FollowerSf2(msg)) => msg,
            Some(m) => return Err(PRFError::UnexpectedMessage(m)),
            None => {
                return Err(PRFError::from(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "stream closed unexpectedly",
                )))
            }
        };

        let vd = core.next(msg);

        Ok(vd)
    }
}
