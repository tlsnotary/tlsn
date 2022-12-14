// This example demonstrates how to securely and privately transfer data using OT extension.
// In practical situations data would be communicated over a channel such as TCP.
// For simplicity, this example shows how to use OT components in memory.

use mpc_core::{
    block::Block,
    ot::dh_ot::{DhOtReceiver, DhOtSender},
};
use rand::thread_rng;

pub fn main() {
    let mut rng = thread_rng();

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

    // First the sender creates a setup message and passes it to sender
    let mut sender = DhOtSender::default();
    let setup = sender.setup(&mut rng).unwrap();

    // Receiver takes sender's setup and creates its own setup message
    let mut receiver = DhOtReceiver::default();
    let setup = receiver.setup(&mut rng, &choice, setup).unwrap();

    // Finally, sender encrypts their inputs and sends them to receiver
    let payload = sender.send(&inputs, setup).unwrap();

    // Receiver takes the encrypted inputs and is able to decrypt according to their choice bits
    let received = receiver.receive(payload).unwrap();

    println!("Transferred messages: {:?}", received);
}
