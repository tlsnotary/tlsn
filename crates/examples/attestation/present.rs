// This example demonstrates how to build a verifiable presentation from an
// attestation and the corresponding connection secrets. See the `prove.rs`
// example to learn how to acquire an attestation from a Notary.

use tlsn_core::{attestation::Attestation, presentation::Presentation, CryptoProvider, Secrets};
use tlsn_formats::http::HttpTranscript;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read attestation from disk.
    let attestation: Attestation =
        bincode::deserialize(&std::fs::read("example.attestation.tlsn")?)?;

    // Read secrets from disk.
    let secrets: Secrets = bincode::deserialize(&std::fs::read("example.secrets.tlsn")?)?;

    // Parse the HTTP transcript.
    let transcript = HttpTranscript::parse(secrets.transcript())?;

    // Build a transcript proof.
    let mut builder = secrets.transcript_proof_builder();

    let request = &transcript.requests[0];
    // Reveal the structure of the request without the headers or body.
    builder.reveal_sent(&request.without_data())?;
    // Reveal the request target.
    builder.reveal_sent(&request.request.target)?;
    // Reveal all headers except the value of the User-Agent header.
    for header in &request.headers {
        if !header.name.as_str().eq_ignore_ascii_case("User-Agent") {
            builder.reveal_sent(header)?;
        } else {
            builder.reveal_sent(&header.without_value())?;
        }
    }
    // Reveal the entire response.
    builder.reveal_recv(&transcript.responses[0])?;

    let transcript_proof = builder.build()?;

    // Use default crypto provider to build the presentation.
    let provider = CryptoProvider::default();

    let mut builder = attestation.presentation_builder(&provider);

    builder
        .identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);

    let presentation: Presentation = builder.build()?;

    // Write the presentation to disk.
    std::fs::write(
        "example.presentation.tlsn",
        bincode::serialize(&presentation)?,
    )?;

    println!("Presentation built successfully!");
    println!("The presentation has been written to `example.presentation.tlsn`.");

    Ok(())
}
