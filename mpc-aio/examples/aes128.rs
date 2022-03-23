use mpc_aio::garble::*;
use mpc_aio::ot::*;
use mpc_core::circuit::{Circuit, CircuitInput};
use mpc_core::garble::{evaluator::*, generator::*};
use mpc_core::ot::{OtReceiverCore, OtSenderCore};
use mpc_core::utils::boolvec_to_string;
use tokio;
use tokio::net::UnixStream;

async fn garble(stream: UnixStream, circ: Circuit) {
    let (mut ws, _) = tokio_tungstenite::client_async("ws://local/garble", stream)
        .await
        .expect("Error during the websocket handshake occurred");

    println!("Generator: Websocket connected");

    let gen_inputs: Vec<CircuitInput> = (0..128)
        .map(|i| CircuitInput {
            id: i,
            value: false,
        })
        .collect();

    println!(
        "Generator: Inputs {}",
        boolvec_to_string(
            &gen_inputs
                .iter()
                .map(|input| input.value)
                .collect::<Vec<bool>>()
        )
    );

    let eval_input_idx: Vec<usize> = (128..256).collect();

    let gen = HalfGateGenerator::new();
    let mut async_gen = Generator::new(OtSender::new(OtSenderCore::default()));
    async_gen
        .garble(&mut ws, &circ, &gen, &gen_inputs, &eval_input_idx)
        .await
        .unwrap();

    println!("Generator: Successfully sent garbled circuit")
}

async fn evaluate(stream: UnixStream, circ: Circuit) -> Result<Vec<bool>, ()> {
    let mut ws = tokio_tungstenite::accept_async(stream)
        .await
        .expect("Error during the websocket handshake occurred");

    println!("Evaluator: Websocket connected");

    let ev_inputs: Vec<CircuitInput> = (128..256)
        .map(|i| CircuitInput {
            id: i,
            value: false,
        })
        .collect();

    println!(
        "Evaluator: Inputs {}",
        boolvec_to_string(
            &ev_inputs
                .iter()
                .map(|input| input.value)
                .collect::<Vec<bool>>()
        )
    );

    let ev = HalfGateEvaluator::new();
    let mut async_ev = Evaluator::new(OtReceiver::new(OtReceiverCore::default()));

    let values = async_ev
        .evaluate(&mut ws, &circ, &ev, &ev_inputs)
        .await
        .unwrap();

    println!("Received: {}", boolvec_to_string(&values));

    Ok(values)
}

#[tokio::main]
async fn main() {
    let circ = Circuit::load("../mpc-core/circuits/protobuf/aes_128_reverse.bin").unwrap();

    // In this example we will setup a websocket connection over Unix channels, this is typically done over TCP
    let (unix_s, unix_r) = UnixStream::pair().unwrap();

    let garble = garble(unix_s, circ.clone());
    let evaluate = evaluate(unix_r, circ);

    let _ = tokio::join!(
        tokio::spawn(async move { garble.await }),
        tokio::spawn(async move { evaluate.await })
    );
}
