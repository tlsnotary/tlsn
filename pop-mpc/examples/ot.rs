// This example demonstrates how to securely and privately transfer data using OT extension.
// In practical situations data would be communicated over a channel such as TCP.
// For simplicity, this example shows how to use OT components in memory.

use aes::cipher::{generic_array::GenericArray, NewBlockCipher};
use aes::Aes128;
use pop_mpc::block::Block;
use pop_mpc::ot::{OTReceiver, OTSender};
use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

pub fn main() {
    // Receiver choice bits
    let choice = vec![false, true, false, false, true, true, false, true];

    println!("Receiver chooses: {:?}", &choice);

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

    // Setup RNGs and Ciphers for both sender and receiver
    let s_rng = ChaCha12Rng::from_entropy();
    let s_cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
    let r_rng = ChaCha12Rng::from_entropy();
    let r_cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));

    // First the receiver creates a setup message and passes it to sender
    let mut receiver = OTReceiver::new(r_rng, r_cipher);
    let base_sender_setup = receiver.base_setup();

    // Sender takes receivers' setup and creates its own setup message
    let mut sender = OTSender::new(s_rng, s_cipher, base_sender_setup);
    let base_receiver_setup = sender.base_setup();

    // Now the receiver generates some seeds from senders' setup and uses OT to transfer them
    let send_seeds = receiver.base_send_seeds(base_receiver_setup);
    sender.base_receive_seeds(send_seeds);

    // Receiver generates OT extension setup and passes it to sender
    let receiver_setup = receiver.extension_setup(&choice);

    // Sender takes receivers' setup and runs its own extension setup
    sender.extension_setup(receiver_setup);

    // Finally, sender encrypts their inputs and sends them to receiver
    let send = sender.send(&inputs);

    // Receiver takes the encrypted inputs and is able to decrypt according to their choice bits
    let receive = receiver.receive(&choice, send);

    println!("Transferred messages: {:?}", receive.values);
}
