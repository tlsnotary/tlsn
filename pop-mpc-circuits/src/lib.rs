pub enum CircuitFiles {
    Aes128Reverse,
    Aes128,
    Adder64,
}

impl CircuitFiles {
    pub fn get_path(c: CircuitFiles) -> String {
        match c {
            Self::Aes128Reverse => concat!(env!("OUT_DIR"), "/aes_128_reverse.bin").to_string(),
            Self::Aes128 => concat!(env!("OUT_DIR"), "/aes_128.bin").to_string(),
            Self::Adder64 => concat!(env!("OUT_DIR"), "/adder64.bin").to_string(),
        }
    }
}
