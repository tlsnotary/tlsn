// This example demonstrates how to build a verifiable presentation from an
// attestation and the corresponding connection secrets. See the `prove.rs`
// example to learn how to acquire an attestation from a Notary.

use hyper::header;
use spansy::{
    json::{JsonValue, Object},
    Spanned,
};
use tlsn_core::{
    attestation::Attestation,
    presentation::Presentation,
    transcript::{self, Direction, TranscriptProofBuilder},
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

    let response = &transcript.responses[0];
    let content = &transcript.responses[0].body.as_ref().unwrap().content;
    // dbg!(content);

    builder.reveal_recv(&response.without_data())?;
    for header in &response.headers {
        builder.reveal_recv(header)?;
    }

    fn reveal(
        json: &JsonValue,
        builder: &mut TranscriptProofBuilder<'_>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match json {
            JsonValue::Object(v) => {
                for child in v.elems.iter() {
                    // FIXME: revealing key is not supported yet
                    // builder.reveal_recv(&child.key)?;

                    reveal(&child.value, builder)?;
                }
            }
            // JsonValue::Array(a) => {
            //     for child in a.elems.iter() {
            //         reveal(&child, builder)?;
            //     }
            // }
            JsonValue::String(s) => {
                builder.reveal_recv(s)?;
            }
            JsonValue::Number(n) => {
                builder.reveal_recv(n)?;
            }
            _ => {
                // todo!()
            }
        }
        Ok(())
    }

    match content {
        tlsn_formats::http::BodyContent::Json(json) => {
            // reveal(json, &mut builder)?;

            // let test = json
            //     .span()
            //     .to_range_set()
            //     .difference(&json.get("id").unwrap().span().to_range_set());

            // let xxx = RangeSet::new(&vec![542..562]);
            // builder.reveal_recv(&xxx);

            let reveal_all = false;
            if reveal_all {
                builder.reveal_recv(&transcript.responses[0])?;
            } else {
                builder.reveal_recv(json.get("id").unwrap())?;
                builder.reveal_recv(json.get("information.name").unwrap())?;
                builder.reveal_recv(json.get("meta.version").unwrap())?;
            }
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
            // builder.reveal_recv(s)?;
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
