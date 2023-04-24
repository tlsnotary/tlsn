//! Traits for transferring encodings via oblivious transfer.

use async_trait::async_trait;
use mpc_circuits::types::Value;
use mpc_core::Block;
use mpc_garble_core::{encoding_state, EncodedValue, Label};
use utils::bits::ToBitsIter;

/// A trait for sending encodings via oblivious transfer.
#[async_trait]
pub trait OTSendEncoding {
    /// Sends encodings to the receiver.
    async fn send(
        &self,
        id: &str,
        input: Vec<EncodedValue<encoding_state::Full>>,
    ) -> Result<(), mpc_ot::OTError>;
}

#[async_trait]
impl<T> OTSendEncoding for T
where
    T: mpc_ot::ObliviousSend<[Block; 2]> + Send + Sync,
{
    async fn send(
        &self,
        id: &str,
        input: Vec<EncodedValue<encoding_state::Full>>,
    ) -> Result<(), mpc_ot::OTError> {
        let blocks = input
            .into_iter()
            .flat_map(|v| v.iter_blocks().collect::<Vec<_>>())
            .collect();
        self.send(id, blocks).await
    }
}

/// A trait for receiving encodings via oblivious transfer.
#[async_trait]
pub trait OTReceiveEncoding {
    /// Receives encodings from the sender.
    async fn receive(
        &self,
        id: &str,
        choice: Vec<Value>,
    ) -> Result<Vec<EncodedValue<encoding_state::Active>>, mpc_ot::OTError>;
}

#[async_trait]
impl<T> OTReceiveEncoding for T
where
    T: mpc_ot::ObliviousReceive<bool, Block> + Send + Sync,
{
    async fn receive(
        &self,
        id: &str,
        choice: Vec<Value>,
    ) -> Result<Vec<EncodedValue<encoding_state::Active>>, mpc_ot::OTError> {
        let mut blocks = self
            .receive(
                id,
                choice
                    .iter()
                    .flat_map(|value| value.clone().into_lsb0_iter())
                    .collect(),
            )
            .await?;
        let encodings = choice
            .iter()
            .map(|value| {
                let labels = blocks
                    .drain(..value.value_type().len())
                    .map(Label::new)
                    .collect::<Vec<_>>();
                EncodedValue::<encoding_state::Active>::from_labels(value.value_type(), &labels)
                    .expect("label length should match value length")
            })
            .collect();

        Ok(encodings)
    }
}

/// A trait for verifying encodings sent via oblivious transfer.
#[async_trait]
pub trait OTVerifyEncoding {
    /// Verifies that the encodings sent by the sender are correct.
    async fn verify(
        &self,
        id: &str,
        input: Vec<EncodedValue<encoding_state::Full>>,
    ) -> Result<(), mpc_ot::OTError>;
}

#[async_trait]
impl<T> OTVerifyEncoding for T
where
    T: mpc_ot::ObliviousVerify<[Block; 2]> + Send + Sync,
{
    async fn verify(
        &self,
        id: &str,
        input: Vec<EncodedValue<encoding_state::Full>>,
    ) -> Result<(), mpc_ot::OTError> {
        let blocks = input
            .into_iter()
            .flat_map(|v| v.iter_blocks().collect::<Vec<_>>())
            .collect();
        self.verify(id, blocks).await
    }
}

/// A trait for verifiable oblivious transfer of encodings.
pub trait VerifiableOTSendEncoding: OTSendEncoding + mpc_ot::ObliviousReveal {}

impl<T> VerifiableOTSendEncoding for T where T: OTSendEncoding + mpc_ot::ObliviousReveal {}

/// A trait for verifiable oblivious transfer of encodings.
pub trait VerifiableOTReceiveEncoding: OTReceiveEncoding + OTVerifyEncoding {}

impl<T> VerifiableOTReceiveEncoding for T where T: OTReceiveEncoding + OTVerifyEncoding {}

#[cfg(test)]
mod tests {
    use super::*;

    use mpc_circuits::circuits::AES128;
    use mpc_garble_core::{ChaChaEncoder, Encoder};
    use mpc_ot::mock::mock_ot_pair;

    #[tokio::test]
    async fn test_encoding_transfer() {
        let encoder = ChaChaEncoder::new([0u8; 32]);
        let (sender, receiver) = mock_ot_pair();

        let inputs = AES128
            .inputs()
            .iter()
            .enumerate()
            .map(|(id, value)| encoder.encode_by_type(id as u64, &value.value_type()))
            .collect::<Vec<_>>();
        let choices = vec![Value::from([42u8; 16]), Value::from([69u8; 16])];

        sender.send("", inputs.clone()).await.unwrap();
        let received = receiver.receive("", choices.clone()).await.unwrap();

        let expected = choices
            .into_iter()
            .zip(inputs)
            .map(|(choice, full)| full.select(choice).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(received, expected);
    }
}
