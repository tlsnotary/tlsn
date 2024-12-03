use std::{env, process::Command, thread, time::Duration};

use tlsn_benches::{clean_up, set_up};

fn main() {
    let args: Vec<String> = env::args().collect();
    let is_memory_profiling = args.contains(&"--memory-profiling".to_string());

    let (prover_path, verifier_path) = if is_memory_profiling {
        (
            std::env::var("PROVER_MEMORY_PATH")
                .unwrap_or_else(|_| "../../../target/release/prover-memory".to_string()),
            std::env::var("VERIFIER_MEMORY_PATH")
                .unwrap_or_else(|_| "../../../target/release/verifier-memory".to_string()),
        )
    } else {
        (
            std::env::var("PROVER_PATH")
                .unwrap_or_else(|_| "../../../target/release/prover".to_string()),
            std::env::var("VERIFIER_PATH")
                .unwrap_or_else(|_| "../../../target/release/verifier".to_string()),
        )
    };

    if let Err(e) = set_up() {
        println!("Error setting up: {}", e);
        clean_up();
    }

    // Run prover and verifier binaries in parallel.
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

    // Allow the verifier some time to start listening before the prover attempts to
    // connect.
    thread::sleep(Duration::from_secs(1));

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

    // Wait for both to finish.
    _ = prover.wait();
    _ = verifier.wait();

    clean_up();
}
