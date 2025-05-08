use eyre::{eyre, Result};
use serde::de::DeserializeOwned;
use std::path::Path;

/// Parse a yaml configuration file into a struct
pub fn parse_config_file<T: DeserializeOwned>(location: &str) -> Result<T> {
    let file = std::fs::File::open(location)?;
    let config: T = serde_yaml::from_reader(file)?;
    Ok(config)
}

/// Parse a csv file into a vec of structs
pub fn parse_csv_file<T: DeserializeOwned>(location: &str) -> Result<Vec<T>> {
    let file = std::fs::File::open(location)?;
    let mut reader = csv::Reader::from_reader(file);
    let mut table: Vec<T> = Vec::new();
    for result in reader.deserialize() {
        let record: T = result?;
        table.push(record);
    }
    Ok(table)
}

/// Prepend a file path with a base directory if the path is not absolute.
pub fn prepend_file_path<S: AsRef<str>>(file_path: S, base_dir: S) -> Result<String> {
    let path = Path::new(file_path.as_ref());
    if !path.is_absolute() {
        Ok(Path::new(base_dir.as_ref())
            .join(path)
            .to_str()
            .ok_or_else(|| eyre!("Failed to convert path to str"))?
            .to_string())
    } else {
        Ok(file_path.as_ref().to_string())
    }
}

#[cfg(test)]
mod test {

    use crate::{
        auth::AuthorizationWhitelistRecord,
        config::NotaryServerProperties,
        util::{parse_csv_file, prepend_file_path},
    };

    use super::{parse_config_file, Result};

    #[test]
    fn test_parse_config_file() {
        let location = "../tests-integration/fixture/config/config.yaml";
        let config: Result<NotaryServerProperties> = parse_config_file(location);
        assert!(
            config.is_ok(),
            "Could not open file or read the file's values."
        );
    }

    #[test]
    fn test_parse_csv_file() {
        let location = "../tests-integration/fixture/auth/whitelist.csv";
        let table: Result<Vec<AuthorizationWhitelistRecord>> = parse_csv_file(location);
        assert!(
            table.is_ok(),
            "Could not open csv or read the csv's values."
        );
    }

    #[test]
    fn test_prepend_file_path() {
        let base_dir = "/base/dir";
        let relative_path = "relative/path";
        let absolute_path = "/absolute/path";

        let result = prepend_file_path(relative_path, base_dir);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "/base/dir/relative/path");

        let result = prepend_file_path(absolute_path, base_dir);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "/absolute/path");
    }
}
