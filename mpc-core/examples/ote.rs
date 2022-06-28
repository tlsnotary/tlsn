// This example demonstrates how to securely and privately transfer data using OT extension.
// In practical situations data would be communicated over a channel such as TCP.
// For simplicity, this example shows how to use OT components in memory.

use mpc_core::block::Block;
use mpc_core::ot::extension::{
    kos15::{Kos15Receiver, Kos15Sender},
    ExtReceiveCore, ExtSendCore,
};

pub fn main() {
    // Receiver choice bits
    let choice = vec![false, true, false, false, true, true, false, true];

    println!("Receiver choices: {:?}", &choice);

    // Sender messages the receiver chooses from
    let inputs = [
        [Block::new(0), Block::new(1)],
        [Block::new(2), Block::new(3)],
        [Block::new(4), Block::new(5)],
        [Block::new(6), Block::new(7)],
        [Block::new(8), Block::new(9)],
        [Block::new(10), Block::new(11)],
        [Block::new(12), Block::new(13)],
        [Block::new(14), Block::new(15)],
    ];

    println!("Sender inputs: {:?}", &inputs);

    // First the receiver creates a setup message and passes it to sender
    let mut receiver = Kos15Receiver::new(inputs.len());
    let base_sender_setup = receiver.base_setup().unwrap();

    // Sender takes receiver's setup and creates its own setup message
    let mut sender = Kos15Sender::new(inputs.len());
    let base_receiver_setup = sender.base_setup(base_sender_setup).unwrap();

    // Now the receiver generates some seeds from sender's setup and uses OT to transfer them
    let base_payload = receiver.base_send(base_receiver_setup).unwrap();
    sender.base_receive(base_payload).unwrap();

    // Receiver generates OT extension setup and passes it to sender
    let receiver_setup = receiver.extension_setup(&choice).unwrap();

    // Sender takes receiver's setup and runs its own extension setup
    sender.extension_setup(receiver_setup).unwrap();

    // Finally, sender encrypts their inputs and sends them to receiver
    let payload = sender.send(&inputs).unwrap();

    // Receiver takes the encrypted inputs and is able to decrypt according to their choice bits
    let received = receiver.receive(payload).unwrap();

    println!("Transferred messages: {:?}", received);
}
