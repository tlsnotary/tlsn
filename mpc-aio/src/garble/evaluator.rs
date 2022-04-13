use super::GarbleError;
use crate::ot::OTReceive;
use mpc_core::circuit::{Circuit, CircuitInput};
use mpc_core::garble::circuit::InputLabel;
use mpc_core::garble::evaluator::GarbledCircuitEvaluator;
use mpc_core::garble::GarbleMessage;

use aes::cipher::{generic_array::GenericArray, NewBlockCipher};
use aes::Aes128;
use futures_util::{Sink, Stream, StreamExt};
use std::io::Error as IOError;
use std::io::ErrorKind;

pub struct Evaluator<S> {
    stream: S,
}

impl<
        S: Sink<GarbleMessage> + Stream<Item = Result<GarbleMessage, E>> + Send + Unpin,
        E: std::fmt::Debug,
    > Evaluator<S>
where
    GarbleError: From<<S as Sink<GarbleMessage>>::Error>,
    GarbleError: From<E>,
{
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    pub async fn evaluate<V: GarbledCircuitEvaluator>(
        &mut self,
        ot: &mut impl OTReceive,
        circ: &Circuit,
        ev: &V,
        inputs: &Vec<CircuitInput>,
    ) -> Result<Vec<bool>, GarbleError> {
        let mut cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));

        let gc = match self.stream.next().await {
            Some(Ok(GarbleMessage::GarbledCircuit(m))) => m,
            #[allow(unreachable_patterns)]
            Some(Ok(m)) => return Err(GarbleError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };

        let choice: Vec<bool> = inputs.iter().map(|input| input.value).collect();
        let input_labels = ot.receive(choice.as_slice()).await.unwrap();
        let input_labels: Vec<InputLabel> = input_labels
            .into_iter()
            .zip(inputs.iter())
            .map(|(label, input)| InputLabel {
                id: input.id,
                label,
            })
            .collect();

        let values = ev
            .eval(&mut cipher, circ, &gc.into(), &input_labels)
            .unwrap();

        Ok(values)
    }
}
