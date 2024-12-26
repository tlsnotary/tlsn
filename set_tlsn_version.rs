#!/usr/bin/env cargo +nightly -Zscript
---
[package]
name = "set_tlsn_version"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
clap = { version = "4.0", features = ["derive"] }
serde_yaml = "0.9"
toml_edit = "0.22.22"
walkdir = "2.5.0"
---

// This scripts sets the TLSNotary version in all relevant files. Run it with:
// ./set_tlsn_version <version>

use clap::Parser;
use serde_yaml::Value;
use std::fs::{self, read_to_string};
use std::path::Path;
use toml_edit::{value, DocumentMut};
use walkdir::WalkDir;

#[derive(Parser)]
#[command(name = "set_tlsn_version")]
#[command(about = "Sets the TLSNotary version in all relevant files", long_about = None)]
struct Args {
    /// Version number to set (example: 0.1.0-alpha.8)
    version: String,

    /// Workspace path (default is current directory)
    #[arg(short, long, default_value = ".")]
    workspace: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Process all Cargo.toml files in the workspace
    for entry in WalkDir::new(&args.workspace)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name() == "Cargo.toml")
    {
        if let Err(e) = update_version_in_cargo_toml(entry.path(), &args.version) {
            eprintln!(
                "Failed to update version in {}: {}",
                entry.path().display(),
                e
            );
        }
    }

    let open_api_path = Path::new(&args.workspace).join("crates/notary/server/openapi.yaml");
    update_version_in_open_api(&open_api_path, &args.version)?;

    println!("Version update process completed.");
    Ok(())
}

/// Update the version in the Cargo.toml file
///
/// Skip files with "publish = false" or "version = 0.0.0"
fn update_version_in_cargo_toml(
    cargo_toml_path: &Path,
    new_version: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let cargo_toml_content = read_to_string(cargo_toml_path)
        .map_err(|e| format!("Failed to read {}: {}", cargo_toml_path.display(), e))?;

    let mut doc = cargo_toml_content.parse::<DocumentMut>().map_err(|e| {
        format!(
            "Invalid TOML format in {}: {}",
            cargo_toml_path.display(),
            e
        )
    })?;

    if let Some(package) = doc.get_mut("package") {
        if package.get("publish").and_then(|p| p.as_bool()) == Some(false) {
            return Ok(());
        }

        if let Some(version) = package.get_mut("version") {
            if version.as_str() == Some("0.0.0") {
                return Err(format!(
                    "\"version\" is \"0.0.0\" and \"publish\" is true in {}",
                    cargo_toml_path.display()
                )
                .into());
            }

            *version = value(new_version);
            fs::write(cargo_toml_path, doc.to_string())
                .map_err(|e| format!("Failed to write {}: {}", cargo_toml_path.display(), e))?;
            println!("Updated version in {}", cargo_toml_path.display());
        }
    }

    Ok(())
}

/// Update the version in the OpenAPI yaml file
fn update_version_in_open_api(
    path: &Path,
    new_version: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let yaml_content =
        read_to_string(path).map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

    let mut doc: Value = serde_yaml::from_str(&yaml_content)
        .map_err(|e| format!("Invalid YAML format in {}: {}", path.display(), e))?;

    if let Some(info) = doc.get_mut("info") {
        if let Some(version) = info.get_mut("version") {
            *version = Value::String(new_version.to_string());
            let updated_yaml = serde_yaml::to_string(&doc)
                .map_err(|e| format!("Failed to serialize YAML for {}: {}", path.display(), e))?;
            fs::write(path, updated_yaml)
                .map_err(|e| format!("Failed to write {}: {}", path.display(), e))?;
            println!("Updated version in {}", path.display());
        }
    }

    Ok(())
}
