use std::process::Command;

fn main() {
    // Used to extract latest HEAD commit hash and timestamp for the /info endpoint
    let output = Command::new("git")
        .args(["show", "HEAD", "-s", "--format=%H,%cI"])
        .output()
        .expect("Git command to get commit hash and timestamp should work during build process");

    let output_string =
        String::from_utf8(output.stdout).expect("Git command should produce valid string output");

    let (commit_hash, commit_timestamp) = output_string
        .as_str()
        .split_once(',')
        .expect("Git commit hash and timestamp string output should be comma separated");

    // Pass these 2 values as env var to the program
    println!("cargo:rustc-env=GIT_COMMIT_HASH={}", commit_hash);
    println!("cargo:rustc-env=GIT_COMMIT_TIMESTAMP={}", commit_timestamp);
}
