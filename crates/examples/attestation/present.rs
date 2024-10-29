// This example demonstrates how to build a verifiable presentation from an
// attestation and the corresponding connection secrets. See the `prove.rs`
// example to learn how to acquire an attestation from a Notary.

use hyper::header;
use tlsn_core::{attestation::Attestation, presentation::Presentation, CryptoProvider, Secrets};
use tlsn_examples::ExampleType;
use tlsn_formats::http::HttpTranscript;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// What data to notarize
    #[clap(default_value_t, value_enum)]
    example_type: ExampleType,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    create_presentation(&args.example_type).await
}

async fn create_presentation(example_type: &ExampleType) -> Result<(), Box<dyn std::error::Error>> {
    let attestation_path = tlsn_examples::get_file_path(example_type, "attestation");
    let secrets_path = tlsn_examples::get_file_path(example_type, "secrets");

    // Read attestation from disk.
    let attestation: Attestation = bincode::deserialize(&std::fs::read(attestation_path)?)?;

    // Read secrets from disk.
    let secrets: Secrets = bincode::deserialize(&std::fs::read(secrets_path)?)?;

    // Parse the HTTP transcript.
    let transcript = HttpTranscript::parse(secrets.transcript())?;

    // Build a transcript proof.
    let mut builder = secrets.transcript_proof_builder();

    let request = &transcript.requests[0];
    // Reveal the structure of the request without the headers or body.
    builder.reveal_sent(&request.without_data())?;
    // Reveal the request target.
    builder.reveal_sent(&request.request.target)?;
    // Reveal all headers except the values of the User-Agent and Authorization.
    for header in &request.headers {
        if !(header
            .name
            .as_str()
            .eq_ignore_ascii_case(header::USER_AGENT.as_str())
            || header
                .name
                .as_str()
                .eq_ignore_ascii_case(header::AUTHORIZATION.as_str()))
        {
            builder.reveal_sent(header)?;
        } else {
            builder.reveal_sent(&header.without_value())?;
        }
    }

    // Reveal only parts of the response
    let response = &transcript.responses[0];
    builder.reveal_recv(&response.without_data())?;
    for header in &response.headers {
        builder.reveal_recv(header)?;
    }

    let content = &response.body.as_ref().unwrap().content;
    match content {
        tlsn_formats::http::BodyContent::Json(json) => {
            // For experimentation, reveal the entire response or just a selection
            let reveal_all = false;
            if reveal_all {
                builder.reveal_recv(response)?;
            } else {
                builder.reveal_recv(json.get("id").unwrap())?;
                builder.reveal_recv(json.get("information.name").unwrap())?;
                builder.reveal_recv(json.get("meta.version").unwrap())?;
            }
        }
        tlsn_formats::http::BodyContent::Unknown(span) => {
            builder.reveal_recv(span)?;
        }
        _ => {}
    }

    let transcript_proof = builder.build()?;

    // Use default crypto provider to build the presentation.
    let provider = CryptoProvider::default();

    let mut builder = attestation.presentation_builder(&provider);

    builder
        .identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);

    let presentation: Presentation = builder.build()?;

    let presentation_path = tlsn_examples::get_file_path(example_type, "presentation");

    // Write the presentation to disk.
    std::fs::write(&presentation_path, bincode::serialize(&presentation)?)?;

    println!("Presentation built successfully!");
    println!("The presentation has been written to `{presentation_path}`.");

    Ok(())
}
