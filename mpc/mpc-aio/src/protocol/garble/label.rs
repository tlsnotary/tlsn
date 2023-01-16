use crate::protocol::ot::{OTError, ObliviousReceive, ObliviousSend, ObliviousVerify};
use async_trait::async_trait;
use mpc_circuits::{InputValue, WireGroup};
use mpc_core::{
    garble::{ActiveInputLabels, FullInputLabels},
    Block,
};

#[derive(Debug, thiserror::Error)]
pub enum WireLabelError {
    #[error("error occurred during OT")]
    OTError(#[from] OTError),
    #[error("core error")]
    CoreError(#[from] mpc_core::garble::Error),
    #[error("Core label error: {0:?}")]
    CoreLabelError(#[from] mpc_core::garble::LabelError),
}

#[async_trait]
impl<T> ObliviousSend<FullInputLabels> for T
where
    T: Send + ObliviousSend<[Block; 2]>,
{
    async fn send(&mut self, inputs: Vec<FullInputLabels>) -> Result<(), OTError> {
        self.send(
            inputs
                .into_iter()
                .map(|labels| labels.blocks())
                .flatten()
                .collect::<Vec<[Block; 2]>>(),
        )
        .await
    }
}

#[async_trait]
impl<T> ObliviousReceive<InputValue, ActiveInputLabels> for T
where
    T: Send + ObliviousReceive<bool, Block>,
{
    async fn receive(
        &mut self,
        choices: Vec<InputValue>,
    ) -> Result<Vec<ActiveInputLabels>, OTError> {
        let choice_bits = choices
            .iter()
            .map(|value| value.value().to_lsb0_bits())
            .flatten()
            .collect::<Vec<bool>>();

        let mut blocks = self.receive(choice_bits).await?;

        Ok(choices
            .into_iter()
            .map(|value| {
                ActiveInputLabels::from_blocks(
                    value.group().clone(),
                    blocks.drain(..value.len()).collect(),
                )
                .expect("Input labels should be valid")
            })
            .collect())
    }
}

#[async_trait]
impl<T> ObliviousVerify<FullInputLabels> for T
where
    T: Send + ObliviousVerify<[Block; 2]>,
{
    async fn verify(self, input: Vec<FullInputLabels>) -> Result<(), OTError> {
        self.verify(
            input
                .into_iter()
                .map(|labels| labels.blocks())
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
    use mpc_core::garble::FullInputLabelsSet;
    use rand::thread_rng;

    #[tokio::test]
    async fn test_wire_label_transfer() {
        let circ = Circuit::load_bytes(ADDER_64).unwrap();
        let full_labels = FullInputLabelsSet::generate(&mut thread_rng(), &circ, None);

        let receiver_labels = full_labels[1].clone();

        let value = circ.input(1).unwrap().to_value(4u64).unwrap();
        let expected = receiver_labels.select(value.value()).unwrap();

        let (mut sender, mut receiver) = mock_ot_pair::<Block>();
        sender.send(vec![receiver_labels]).await.unwrap();
        let received = receiver.receive(vec![value]).await.unwrap();

        assert_eq!(received[0], expected);
    }
}
