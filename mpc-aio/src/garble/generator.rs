use super::GarbleError;
use crate::ot::OTSend;
use mpc_core::circuit::{Circuit, CircuitInput};
use mpc_core::garble::generator::GarbledCircuitGenerator;
use mpc_core::garble::GarbleMessage;
use mpc_core::Block;

use aes::cipher::{generic_array::GenericArray, NewBlockCipher};
use aes::Aes128;
use futures_util::{Sink, SinkExt, Stream};
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

pub struct Generator<S> {
    stream: S,
}

impl<
        S: Sink<GarbleMessage> + Stream<Item = Result<GarbleMessage, E>> + Send + Unpin,
        E: std::fmt::Debug,
    > Generator<S>
where
    GarbleError: From<<S as Sink<GarbleMessage>>::Error>,
    GarbleError: From<E>,
{
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    pub async fn garble<G: GarbledCircuitGenerator>(
        &mut self,
        ot: &mut impl OTSend,
        circ: &Circuit,
        gen: &G,
        inputs: &Vec<CircuitInput>,
        eval_input_idx: &Vec<usize>,
    ) -> Result<(), GarbleError> {
        let mut cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
        let mut rng = ChaCha12Rng::from_entropy();
        let complete_gc = gen.garble(&mut cipher, &mut rng, circ)?;
        let gc = complete_gc.to_public(inputs);

        let eval_inputs: Vec<[Block; 2]> = eval_input_idx
            .iter()
            .map(|idx| complete_gc.input_labels[*idx])
            .collect();

        self.stream.send(GarbleMessage::GarbledCircuit(gc)).await?;

        ot.send(eval_inputs.as_slice()).await.unwrap();

        Ok(())
    }
}
