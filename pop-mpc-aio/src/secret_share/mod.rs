use p256::EncodedPoint;
use pop_mpc_core::secret_share::{SecretShare, SecretShareMaster};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{tungstenite::protocol::Message, WebSocketStream};

pub struct AsyncSecretShareMaster;

impl AsyncSecretShareMaster {
    pub fn new() -> Self {
        Self
    }

    pub async fn run<S: AsyncWrite + AsyncRead + Unpin>(
        &mut self,
        point: &EncodedPoint,
        stream: &mut WebSocketStream<S>,
    ) -> Result<SecretShare, ()> {
        let master = SecretShareMaster::new(&point);
        let (message, master) = master.next();

        todo!()
    }
}
