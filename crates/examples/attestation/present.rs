// This example demonstrates how to build a verifiable presentation from an
// attestation and the corresponding connection secrets. See the `prove.rs`
// example to learn how to acquire an attestation from a Notary.

use hyper::header;
use spansy::Spanned;
use tlsn_core::{
    attestation::Attestation,
    presentation::Presentation,
    transcript::{self, Direction},
    CryptoProvider, Secrets,
};
use tlsn_formats::http::HttpTranscript;
use utils::range::{Difference, RangeSet, ToRangeSet};

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
    // Reveal the entire response.
    // builder.reveal_recv(&transcript.responses[0])?;

    dbg!("foo");

    let x = &transcript.responses[0].body.as_ref().unwrap().content;
    // dbg!(x);
    builder.reveal_recv(&transcript.responses[0].without_data())?;

    match x {
        tlsn_formats::http::BodyContent::Json(json) => {
            let id = json.get("id").unwrap();
            let lhs = json.span().to_range_set();
            let rhs = id.span().to_range_set();
            let diff = lhs.difference(&rhs);

            let test = json.get("information.name").unwrap();

            let test = json
                .span()
                .to_range_set()
                .difference(&json.get("id").unwrap().span().to_range_set());

            let transcript_range_set = transcript.responses[0].span().to_range_set();
            let json_range_set = json.span().to_range_set();
            println!("transcript: {:?}", &transcript_range_set);
            println!("Json: {:?}", &json_range_set);

            //works
            // let xxx = RangeSet::new(&vec![542..562]);
            // builder.reveal_recv(&xxx);

            //does not work
            let xxx = RangeSet::new(&vec![542..561]);
            builder.reveal_recv(&xxx)?;

            // if true {
            //     // works
            //     builder.reveal_recv(&transcript_range_set)?;
            //     // builder.reveal_recv(json.get("id").unwrap())?;
            // } else {
            //     // does not work
            //     builder.reveal_recv(&json_range_set)?;
            // }
        }
        tlsn_formats::http::BodyContent::Unknown(span) => {
            // dbg!(&span);
            let information = span.data();
            let information = String::from_utf8_lossy(information);
            let parsed = serde_json::from_str::<serde_json::Value>(&information)?;

            let json = spansy::json::parse_str(&information)?;
            let id = json.get("id").unwrap();
            println!("Reveal: {id:?}");
            let offset = span.indices().min().unwrap();
            let mut s = id.span().indices();
            // s.offset(offset);
            builder.reveal_recv(s)?;
            // println!("Reveal: {:?}", &transcript.responses[0]);
            // builder.reveal_recv(&transcript.responses[0])?;
        }
        _ => {}
    }

    println!("test");
    let transcript_proof = builder.build()?;
    println!("transcript_proof: {transcript_proof:?}");

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
