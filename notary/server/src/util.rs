use eyre::Result;
use serde::de::DeserializeOwned;

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

#[cfg(test)]
mod test {

    use crate::{
        config::NotaryServerProperties, domain::auth::AuthorizationWhitelistRecord,
        util::parse_csv_file,
    };

    use super::{parse_config_file, Result};

    #[test]
    fn test_parse_config_file() {
        let location = "./config/config.yaml";
        let config: Result<NotaryServerProperties> = parse_config_file(location);
        assert!(
            config.is_ok(),
            "Could not open file or read the file's values."
        );
    }

    #[test]
    fn test_parse_csv_file() {
        let location = "./fixture/auth/whitelist.csv";
        let table: Result<Vec<AuthorizationWhitelistRecord>> = parse_csv_file(location);
        assert!(
            table.is_ok(),
            "Could not open csv or read the csv's values."
        );
    }
}
