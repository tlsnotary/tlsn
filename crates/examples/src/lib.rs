use std::fmt;

// Maximum number of bytes that can be sent from prover to server.
pub const MAX_SENT_DATA: usize = 1 << 12;
// Maximum number of bytes that can be received by prover from server.
pub const MAX_RECV_DATA: usize = 1 << 14;

#[derive(clap::ValueEnum, Clone, Default, Debug)]
pub enum ExampleType {
    #[default]
    Json,
    Html,
    Authenticated,
}

impl fmt::Display for ExampleType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub fn get_file_path(example_type: &ExampleType, content_type: &str) -> String {
    let example_type = example_type.to_string().to_ascii_lowercase();
    format!("example-{}.{}.tlsn", example_type, content_type)
}
