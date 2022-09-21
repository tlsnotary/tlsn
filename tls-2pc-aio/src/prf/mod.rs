mod circuits;
mod follower;
mod leader;

use mpc_aio::protocol::garble::GCError;
use tls_2pc_core::msgs::prf::PRFMessage;
use utils_aio::Channel;

pub use follower::PRFFollower;
pub use leader::PRFLeader;

pub type PRFChannel = Box<dyn Channel<PRFMessage, Error = std::io::Error>>;

#[derive(Debug, thiserror::Error)]
pub enum PRFError {
    #[error("error occurred during garbled circuit protocol")]
    GCError(#[from] GCError),
    #[error("io error")]
    IOError(#[from] std::io::Error),
    #[error("unexpected message: {0:?}")]
    UnexpectedMessage(PRFMessage),
}

#[cfg(test)]
mod tests {
    use mpc_aio::protocol::{
        garble::exec::dual::{DualExFollower, DualExLeader},
        ot::mock::mock_ot_pair,
    };
    use utils_aio::duplex::DuplexChannel;

    use super::*;

    #[tokio::test]
    async fn test_prf() {
        let (leader_channel, follower_channel) = DuplexChannel::<GarbleMessage>::new();
        let (leader_sender, follower_receiver) = mock_ot_pair();
        let (follower_sender, leader_receiver) = mock_ot_pair();

        let mut leader =
            DualExLeader::new(Box::new(leader_channel), leader_sender, leader_receiver);
        let mut follower = DualExFollower::new(
            Box::new(follower_channel),
            follower_sender,
            follower_receiver,
        );
        //let leader = PRFLeader::new(channel, gc_exec)
    }
}
