// Clean up the network namespaces and interface pair created by setup_network.rs

use std::process::Command;
use tlsn_benches_tc::*;

fn main() -> Result<(), std::io::Error> {
    // Delete interface pair
    Command::new("sudo")
        .args(&[
            "ip",
            "netns",
            "exec",
            PROVER_NAMESPACE,
            "ip",
            "link",
            "delete",
            PROVER_INTERFACE,
        ])
        .status()?;

    // Delete namespaces
    Command::new("sudo")
        .args(&["ip", "netns", "del", PROVER_NAMESPACE])
        .status()?;
    Command::new("sudo")
        .args(&["ip", "netns", "del", VERIFIER_NAMESPACE])
        .status()?;

    Ok(())
}
