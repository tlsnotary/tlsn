use git2::{Repository, StatusOptions};
use std::env;

fn main() {
    if env::var("GIT_COMMIT_HASH").is_err() {
        let repo = Repository::discover(".").expect("Failed to open repository");
        let commit_hash = get_commit_hash(&repo).expect("Failed to get commit hash");
        let has_changes = check_local_changes(&repo).expect("Failed to check local changes");

        let change_suffix = if has_changes {
            " (with local changes)"
        } else {
            ""
        };

        // Pass value as env var to the notary server
        println!(
            "cargo:rustc-env=GIT_COMMIT_HASH={}{}",
            commit_hash, change_suffix
        );
    }
}

fn get_commit_hash(repo: &Repository) -> Result<String, git2::Error> {
    let head = repo.head()?;
    let commit = head.peel_to_commit()?;
    Ok(commit.id().to_string())
}

fn check_local_changes(repo: &Repository) -> Result<bool, git2::Error> {
    let mut status_options = StatusOptions::new();
    status_options
        .include_untracked(false)
        .include_ignored(false);
    let statuses = repo.statuses(Some(&mut status_options))?;
    Ok(!statuses.is_empty())
}
