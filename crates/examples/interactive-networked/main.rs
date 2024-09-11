use std::{
    io::{BufRead, BufReader},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

fn main() -> std::io::Result<()> {
    let examples_folder = Path::new(env!("CARGO_MANIFEST_DIR"));
    let verifier_dir = examples_folder.join(Path::new("interactive-networked/verifier"));
    let prover_dir = examples_folder.join(Path::new("interactive-networked/prover"));

    const SLEEP_TIME_SECS: u64 = 2; // allow the verifier some extra seconds to start and stop

    // Run the verifier in the background
    println!("Starting the verifier...");
    let mut verifier = run(&verifier_dir, "cargo", &["run", "--release"], "VERIFIER")?;

    // Allow the verifier some time to start
    thread::sleep(Duration::from_secs(SLEEP_TIME_SECS));

    // Run the prover in the foreground
    println!("Starting the prover...");
    let prover_status = run(&prover_dir, "cargo", &["run", "--release"], "PROVER")?.wait()?;

    if prover_status.success() {
        println!("Prover finished successfully.");
    } else {
        eprintln!("Prover finished with errors.");
    }

    // Allow the verifier some time to finish the verification
    thread::sleep(Duration::from_secs(SLEEP_TIME_SECS));

    // Stop the verifier after the prover finishes
    println!("Stopping the verifier...");
    verifier.kill()?;
    println!("Verifier stopped. Script finished.");

    Ok(())
}

fn run(working_dir: &Path, cmd: &str, args: &[&str], prefix: &str) -> std::io::Result<Child> {
    let mut process = Command::new(cmd)
        .args(args)
        .current_dir(working_dir)
        .stdout(Stdio::piped()) // Capture stdout
        .stderr(Stdio::piped()) // Capture stderr
        .spawn()?;

    // Helper function to handle reading from a stream and prefixing its output
    fn handle_output<R: std::io::Read + Send + 'static, F>(stream: R, prefix: String, print_fn: F)
    where
        F: Fn(String) + Send + 'static,
    {
        thread::spawn(move || {
            let reader = BufReader::new(stream);
            for line in reader.lines() {
                if let Ok(line) = line {
                    print_fn(format!("[{}] {}", prefix, line));
                }
            }
        });
    }

    // Prefix stdout
    if let Some(stdout) = process.stdout.take() {
        handle_output(stdout, prefix.to_string(), |line| println!("{}", line));
    }

    // Prefix stderr
    if let Some(stderr) = process.stderr.take() {
        handle_output(stderr, prefix.to_string(), |line| eprintln!("{}", line));
    }

    Ok(process)
}
