use crate::protocol::ot::{OTError, ObliviousReceive, ObliviousSend, ObliviousVerify};
use async_trait::async_trait;
use mpc_circuits::{InputValue, WireGroup};
use mpc_core::{
    garble::{InputLabels, WireLabel, WireLabelPair},
    Block,
};

#[derive(Debug, thiserror::Error)]
pub enum WireLabelError {
    #[error("error occurred during OT")]
    OTError(#[from] OTError),
    #[error("core error")]
    CoreError(#[from] mpc_core::garble::Error),
}

#[async_trait]
impl<T> ObliviousSend<InputLabels<WireLabelPair>> for T
where
    T: Send + ObliviousSend<[Block; 2]>,
{
    async fn send(&mut self, inputs: Vec<InputLabels<WireLabelPair>>) -> Result<(), OTError> {
        self.send(
            inputs
                .into_iter()
                .map(|labels| labels.to_blocks())
                .flatten()
                .collect::<Vec<[Block; 2]>>(),
        )
        .await
    }
}

#[async_trait]
impl<T> ObliviousReceive<InputValue, InputLabels<WireLabel>> for T
where
    T: Send + ObliviousReceive<bool, Block>,
{
    async fn receive(
        &mut self,
        choices: Vec<InputValue>,
    ) -> Result<Vec<InputLabels<WireLabel>>, OTError> {
        let choice_bits = choices
            .iter()
            .map(|value| value.value().to_bits())
            .flatten()
            .collect::<Vec<bool>>();

        let mut labels = self.receive(choice_bits).await?;

        Ok(choices
            .into_iter()
            .map(|value| {
                InputLabels::new(
                    value.group().clone(),
                    &labels
                        .drain(..value.len())
                        .zip(value.wires().iter())
                        .map(|(block, id)| WireLabel::new(*id, block))
                        .collect::<Vec<WireLabel>>(),
                )
                .expect("Input labels should be valid")
            })
            .collect())
    }
}

#[async_trait]
impl<T> ObliviousVerify<InputLabels<WireLabelPair>> for T
where
    T: Send + ObliviousVerify<[Block; 2]>,
{
    async fn verify(self, input: Vec<InputLabels<WireLabelPair>>) -> Result<(), OTError> {
        self.verify(
            input
                .into_iter()
                .map(|labels| labels.to_blocks())
                .flatten()
                .collect(),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ot::mock::mock_ot_pair;
    use mpc_circuits::{Circuit, ADDER_64};
    use rand::thread_rng;

    #[tokio::test]
    async fn test_wire_label_transfer() {
        let circ = Circuit::load_bytes(ADDER_64).unwrap();
        let ((_, receiver_labels), _) =
            InputLabels::generate_split(&mut thread_rng(), &circ, &[0], None).unwrap();
        let value = circ.input(1).unwrap().to_value(4u64).unwrap();
        let expected = receiver_labels[0].select(&value).unwrap();

        let (mut sender, mut receiver) = mock_ot_pair::<Block>();
        sender.send(receiver_labels).await.unwrap();
        let received = receiver.receive(vec![value]).await.unwrap();

        assert_eq!(received[0].as_ref(), expected.as_ref());
    }
}
