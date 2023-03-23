// This example demonstrates how to securely and privately transfer data using Random OT extension.
// Random OT extension allows the sender and receiver to setup the transfer prior to the receiver
// knowing which choices they will want. This is helpful when the receivers choices depend on what
// data they receive via prior choices during the transfer.
// In practical situations data would be communicated over a channel such as TCP.
// For simplicity, this example shows how to use OT components in memory.

use mpc_core::Block;
use mpc_ot_core::extension::{Kos15Receiver, Kos15Sender};

pub fn main() {
    // Sender messages the receiver chooses from
    let inputs = [
        [Block::new(1), Block::new(0)],
        [Block::new(1), Block::new(4)],
        [Block::new(6), Block::new(6)],
        [Block::new(7), Block::new(9)],
        [Block::new(4), Block::new(1)],
        [Block::new(12), Block::new(0)],
        [Block::new(15), Block::new(0)],
        [Block::new(11), Block::new(2)],
    ];

    println!("Sender inputs: {:?}", &inputs);

    // First the receiver creates a setup message and passes it to sender
    let receiver = Kos15Receiver::default();
    let (receiver, base_sender_setup) = receiver.base_setup().unwrap();

    // Sender takes receiver's setup and creates its own setup message
    let sender = Kos15Sender::default();
    let (sender, base_receiver_setup) = sender.base_setup(base_sender_setup).unwrap();

    // Now the receiver generates some seeds from sender's setup and uses OT to transfer them
    let (receiver, base_payload) = receiver.base_send(base_receiver_setup).unwrap();
    let sender = sender.base_receive(base_payload).unwrap();

    // Receiver generates OT extension setup and passes it to sender
    let (mut receiver, receiver_setup) = receiver.rand_extension_setup(256).unwrap();

    // Sender takes receiver's setup and runs its own extension setup
    let mut sender = sender.rand_extension_setup(256, receiver_setup).unwrap();

    let mut received: Vec<Block> = Vec::new();

    // For illustration purposes, here we will show that the receiver can determine
    // their choices depending on what they received in earlier batches
    let initial_choices = vec![false, true];
    let derandomize = receiver.derandomize(&initial_choices).unwrap();
    let initial_payload = sender.rand_send(&inputs[..2], derandomize).unwrap();
    received.append(&mut receiver.receive(initial_payload).unwrap());
    for chunk in inputs[2..].chunks(2) {
        let received_sum: u128 = received.iter().map(|b| b.inner()).sum();
        let choice = received_sum % 2 == 0;
        let derandomize = receiver.derandomize(&[choice, !choice]).unwrap();
        let payload = sender.rand_send(&chunk, derandomize).unwrap();
        received.append(&mut receiver.receive(payload).unwrap());
    }

    println!("Transferred messages: {:?}", received);
}
