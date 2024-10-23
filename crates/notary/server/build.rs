use chrono::DateTime;
use git2::{Commit, Repository, StatusOptions};
use std::{env, error::Error};

fn main() -> Result<(), Box<dyn Error>> {
    if env::var("GIT_COMMIT_HASH").is_err() {
        match get_commithash_with_dirty_suffix() {
            Ok(commit_hash_with_suffix) => {
                // Pass value as env var to the notary server
                println!("cargo:rustc-env=GIT_COMMIT_HASH={commit_hash_with_suffix}");
            }
            Err(e) => {
                eprintln!("Failed to get commit hash in notary server build");
                eprintln!("Fix the error or configure GIT_COMMIT_HASH as environment variable");
                return Err(e.message().into());
            }
        };
    }
    Ok(())
}

fn get_commithash_with_dirty_suffix() -> Result<String, git2::Error> {
    let repo = Repository::discover(".")?;
    let commit = get_commit(&repo)?;
    let commit_hash = commit.id().to_string();
    let _timestamp = get_commit_timestamp(&commit)?;
    let has_changes = check_local_changes(&repo)?;

    if has_changes {
        Ok(format!("{commit_hash} (with local changes)"))
    } else {
        Ok(commit_hash)
    }
}

fn get_commit(repo: &Repository) -> Result<Commit, git2::Error> {
    let head = repo.head()?;
    head.peel_to_commit()
}

fn get_commit_timestamp(commit: &Commit) -> Result<String, git2::Error> {
    let timestamp = commit.time().seconds();
    let date_time = DateTime::from_timestamp(timestamp, 0)
        .ok_or_else(|| git2::Error::from_str("Invalid timestamp"))?;
    Ok(date_time.to_rfc2822())
}

fn check_local_changes(repo: &Repository) -> Result<bool, git2::Error> {
    let mut status_options = StatusOptions::new();
    status_options
        .include_untracked(false)
        .include_ignored(false);
    let statuses = repo.statuses(Some(&mut status_options))?;
    Ok(!statuses.is_empty())
}
