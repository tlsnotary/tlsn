use async_trait::async_trait;
use mpc_core::BlockConvert;
use mpc_share_conversion_core::fields::Field;

#[async_trait]
pub trait OTSendElement<F: Field>: Send + Sync {
    /// Sends elements to the receiver.
    async fn send(&self, id: &str, input: Vec<[F; 2]>) -> Result<(), mpc_ot::OTError>;
}

#[async_trait]
impl<T, F> OTSendElement<F> for T
where
    T: mpc_ot::ObliviousSend<[<F as BlockConvert>::BlockRepr; 2]> + Send + Sync,
    F: Field + Send,
{
    async fn send(&self, id: &str, input: Vec<[F; 2]>) -> Result<(), mpc_ot::OTError> {
        let blocks = input
            .into_iter()
            .map(|v| [v[0].to_blocks(), v[1].to_blocks()])
            .collect();
        self.send(id, blocks).await
    }
}

#[async_trait]
pub trait OTReceiveElement<F: Field>: Send + Sync {
    /// Receives elements from the sender.
    async fn receive(&self, id: &str, choice: Vec<bool>) -> Result<Vec<F>, mpc_ot::OTError>;
}

#[async_trait]
impl<T, F> OTReceiveElement<F> for T
where
    T: mpc_ot::ObliviousReceive<bool, <F as BlockConvert>::BlockRepr> + Send + Sync,
    F: Field,
{
    async fn receive(&self, id: &str, choice: Vec<bool>) -> Result<Vec<F>, mpc_ot::OTError> {
        self.receive(id, choice)
            .await
            .map(|elems| elems.into_iter().map(|v| F::from_blocks(v)).collect())
    }
}
