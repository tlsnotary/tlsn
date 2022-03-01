pub mod errors;

use crate::ot::{AsyncOtReceiver, AsyncOtSender};
use aes::cipher::{generic_array::GenericArray, NewBlockCipher};
use aes::Aes128;
use errors::*;
use futures_util::{SinkExt, StreamExt};
use pop_mpc_core::circuit::{Circuit, CircuitInput};
use pop_mpc_core::garble::circuit::InputLabel;
use pop_mpc_core::garble::{evaluator::*, generator::*};
use pop_mpc_core::ot::{OtReceiver, OtSender};
use pop_mpc_core::proto;
use pop_mpc_core::Block;
use prost::Message as ProtoMessage;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{tungstenite::protocol::Message, WebSocketStream};

pub struct AsyncGenerator<S> {
    ot: AsyncOtSender<S>,
}

pub struct AsyncEvaluator<S> {
    ot: AsyncOtReceiver<S>,
}

impl<OT: OtSender> AsyncGenerator<OT> {
    pub fn new(ot: AsyncOtSender<OT>) -> Self {
        Self { ot }
    }

    pub async fn garble<S: AsyncWrite + AsyncRead + Unpin, G: GarbledCircuitGenerator>(
        &mut self,
        stream: &mut WebSocketStream<S>,
        circ: &Circuit,
        gen: &G,
        inputs: &Vec<CircuitInput>,
        eval_input_idx: &Vec<usize>,
    ) -> Result<(), AsyncGeneratorError> {
        let mut cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
        let mut rng = ChaCha12Rng::from_entropy();
        let complete_gc = gen.garble(&mut cipher, &mut rng, circ).unwrap();
        let gc = complete_gc.to_public(inputs);

        let eval_inputs: Vec<[Block; 2]> = eval_input_idx
            .iter()
            .map(|idx| complete_gc.input_labels[*idx])
            .collect();

        stream
            .send(Message::Binary(
                proto::garble::GarbledCircuit::from(gc).encode_to_vec(),
            ))
            .await
            .unwrap();

        self.ot.send(stream, eval_inputs.as_slice()).await.unwrap();

        Ok(())
    }
}

impl<OT: OtReceiver> AsyncEvaluator<OT> {
    pub fn new(ot: AsyncOtReceiver<OT>) -> Self {
        Self { ot }
    }

    pub async fn evaluate<S: AsyncWrite + AsyncRead + Unpin, E: GarbledCircuitEvaluator>(
        &mut self,
        stream: &mut WebSocketStream<S>,
        circ: &Circuit,
        ev: &E,
        inputs: &Vec<CircuitInput>,
    ) -> Result<Vec<bool>, ()> {
        let mut cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));

        let gc = match stream.next().await {
            Some(message) => {
                proto::garble::GarbledCircuit::decode(message.unwrap().into_data().as_slice())
                    .expect("Expected GarbledCircuit")
            }
            _ => return Err(()),
        };

        let choice: Vec<bool> = inputs.iter().map(|input| input.value).collect();
        let input_labels = self.ot.receive(stream, choice.as_slice()).await.unwrap();
        let input_labels = input_labels
            .into_iter()
            .zip(inputs.iter())
            .map(|(label, input)| InputLabel {
                id: input.id,
                label,
            })
            .collect();

        let values = ev
            .eval(&mut cipher, circ, &gc.into(), input_labels)
            .unwrap();

        Ok(values)
    }
}
