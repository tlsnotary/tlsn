use eyre::Result;
use serde::de::DeserializeOwned;

/// Parse a yaml configuration file into a struct
pub fn parse_config_file<T: DeserializeOwned>(location: &str) -> Result<T> {
    let file = std::fs::File::open(location)?;
    let config: T = serde_yaml::from_reader(file)?;
    Ok(config)
}

#[cfg(test)]
mod test {

    use crate::config::NotaryServerProperties;

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
}
