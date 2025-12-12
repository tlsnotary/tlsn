//! Verifier that receives a presentation over TCP and verifies it.
//! Compiled with getrandom_backend="unsupported" to prove verification
//! doesn't need syscalls.

use std::io::Read;
use std::net::TcpStream;

use tlsn_attestation::{CryptoProvider, presentation::Presentation};

fn main() {
    println!("Verifier connecting to 127.0.0.1:19844...");

    let mut stream = TcpStream::connect("127.0.0.1:19844").unwrap();
    println!("Connected to prover");

    // Read length first
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).unwrap();
    let len = u32::from_be_bytes(len_bytes) as usize;
    println!("Expecting {} bytes", len);

    // Read presentation data
    let mut presentation_bytes = vec![0u8; len];
    stream.read_exact(&mut presentation_bytes).unwrap();
    println!("Received presentation");

    // Deserialize
    let presentation: Presentation = bincode::deserialize(&presentation_bytes).unwrap();
    println!("Deserialized presentation");

    // Verify - this should work without getrandom!
    let provider = CryptoProvider::default();
    let output = presentation.verify(&provider).unwrap();

    println!("Verification SUCCESS!");
    println!("Server name: {:?}", output.server_name);
    println!("Transcript sent length: {}", output.transcript.as_ref().map(|t| t.sent_unsafe().len()).unwrap_or(0));
    println!("Transcript recv length: {}", output.transcript.as_ref().map(|t| t.received_unsafe().len()).unwrap_or(0));
}
