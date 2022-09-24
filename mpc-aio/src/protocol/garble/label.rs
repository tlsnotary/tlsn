use crate::protocol::ot;
use async_trait::async_trait;
use mpc_circuits::InputValue;
use mpc_core::{
    garble::{InputLabels, WireLabel, WireLabelPair},
    Block,
};

#[derive(Debug, thiserror::Error)]
pub enum WireLabelError {
    #[error("error occurred during OT")]
    OTError(#[from] ot::OTError),
    #[error("core error")]
    CoreError(#[from] mpc_core::garble::Error),
}

#[async_trait]
pub trait WireLabelOTSend: ot::ObliviousSend<Inputs = Vec<[Block; 2]>> {
    /// Sends labels using oblivious transfer
    ///
    /// Inputs must be provided sorted ascending by input id
    async fn send_labels(
        &mut self,
        inputs: Vec<InputLabels<WireLabelPair>>,
    ) -> Result<(), WireLabelError> {
        self.send(
            inputs
                .into_iter()
                .map(|labels| {
                    labels
                        .as_ref()
                        .iter()
                        .map(|pair| [*pair.low(), *pair.high()])
                        .collect::<Vec<[Block; 2]>>()
                })
                .flatten()
                .collect::<Vec<[Block; 2]>>(),
        )
        .await
        .map_err(WireLabelError::from)
    }
}

impl<T> WireLabelOTSend for T where T: ot::ObliviousSend<Inputs = Vec<[Block; 2]>> {}

#[async_trait]
pub trait WireLabelOTReceive: ot::ObliviousReceive<Choice = bool, Outputs = Vec<Block>> {
    /// Receives labels using oblivious transfer
    ///
    /// Inputs must be provided sorted ascending by input id
    async fn receive_labels(
        &mut self,
        inputs: Vec<InputValue>,
    ) -> Result<Vec<InputLabels<WireLabel>>, WireLabelError> {
        let choices = inputs
            .iter()
            .map(|value| value.wire_values())
            .flatten()
            .collect::<Vec<bool>>();

        let mut labels = self.receive(&choices).await?;

        inputs
            .into_iter()
            .map(|value| {
                InputLabels::new(
                    value.input().clone(),
                    &labels
                        .drain(..value.len())
                        .zip(value.wires().iter())
                        .map(|(block, id)| WireLabel::new(*id, block))
                        .collect::<Vec<WireLabel>>(),
                )
                .map_err(WireLabelError::from)
            })
            .collect::<Result<Vec<InputLabels<WireLabel>>, WireLabelError>>()
    }
}

impl<T> WireLabelOTReceive for T where T: ot::ObliviousReceive<Choice = bool, Outputs = Vec<Block>> {}

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
        sender.send_labels(receiver_labels).await.unwrap();
        let received = receiver.receive_labels(vec![value]).await.unwrap();

        assert_eq!(received[0].as_ref(), expected.as_ref());
    }
}
