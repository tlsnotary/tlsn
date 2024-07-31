use std::process::Command;

use tlsn_benches::{clean_up, set_up};

fn main() {
    let prover_path =
        std::env::var("PROVER_PATH").unwrap_or_else(|_| "../target/release/prover".to_string());
    let verifier_path =
        std::env::var("VERIFIER_PATH").unwrap_or_else(|_| "../target/release/verifier".to_string());

    if let Err(e) = set_up() {
        println!("Error setting up: {}", e);
        clean_up();
    }

    // Run prover and verifier binaries in parallel
    let Ok(mut verifier) = Command::new("ip")
        .arg("netns")
        .arg("exec")
        .arg("verifier-ns")
        .arg(verifier_path)
        .spawn()
    else {
        println!("Failed to start verifier");
        return clean_up();
    };

    let Ok(mut prover) = Command::new("ip")
        .arg("netns")
        .arg("exec")
        .arg("prover-ns")
        .arg(prover_path)
        .spawn()
    else {
        println!("Failed to start prover");
        return clean_up();
    };

    // Wait for both to finish
    _ = prover.wait();
    _ = verifier.wait();

    clean_up();
}
