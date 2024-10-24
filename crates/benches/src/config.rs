use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(untagged)]
pub enum Field<T> {
    Single(T),
    Multiple(Vec<T>),
}

#[derive(Deserialize)]
pub struct Config {
    pub benches: Vec<Bench>,
}

#[derive(Deserialize)]
pub struct Bench {
    pub name: String,
    pub upload: Field<usize>,
    #[serde(rename = "upload-delay")]
    pub upload_delay: Field<usize>,
    pub download: Field<usize>,
    #[serde(rename = "download-delay")]
    pub download_delay: Field<usize>,
    #[serde(rename = "upload-size")]
    pub upload_size: Field<usize>,
    #[serde(rename = "download-size")]
    pub download_size: Field<usize>,
    #[serde(rename = "defer-decryption")]
    pub defer_decryption: Field<bool>,
}

impl Bench {
    /// Flattens the config into a list of instances
    pub fn flatten(self) -> Vec<BenchInstance> {
        let mut instances = vec![];

        let upload = match self.upload {
            Field::Single(u) => vec![u],
            Field::Multiple(u) => u,
        };

        let upload_delay = match self.upload_delay {
            Field::Single(u) => vec![u],
            Field::Multiple(u) => u,
        };

        let download = match self.download {
            Field::Single(u) => vec![u],
            Field::Multiple(u) => u,
        };

        let download_latency = match self.download_delay {
            Field::Single(u) => vec![u],
            Field::Multiple(u) => u,
        };

        let upload_size = match self.upload_size {
            Field::Single(u) => vec![u],
            Field::Multiple(u) => u,
        };

        let download_size = match self.download_size {
            Field::Single(u) => vec![u],
            Field::Multiple(u) => u,
        };

        let defer_decryption = match self.defer_decryption {
            Field::Single(u) => vec![u],
            Field::Multiple(u) => u,
        };

        for u in upload {
            for ul in &upload_delay {
                for d in &download {
                    for dl in &download_latency {
                        for us in &upload_size {
                            for ds in &download_size {
                                for dd in &defer_decryption {
                                    instances.push(BenchInstance {
                                        name: self.name.clone(),
                                        upload: u,
                                        upload_delay: *ul,
                                        download: *d,
                                        download_delay: *dl,
                                        upload_size: *us,
                                        download_size: *ds,
                                        defer_decryption: *dd,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        instances
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BenchInstance {
    pub name: String,
    pub upload: usize,
    pub upload_delay: usize,
    pub download: usize,
    pub download_delay: usize,
    pub upload_size: usize,
    pub download_size: usize,
    pub defer_decryption: bool,
}
