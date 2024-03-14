use std::collections::VecDeque;

pub struct Env {
    pub defer_decryption: bool,
    pub sizes: VecDeque<usize>,
}

impl Default for Env {
    fn default() -> Self {
        Env {
            defer_decryption: true,
            sizes: VecDeque::from([1024]),
        }
    }
}

pub struct BenchOptions {
    pub defer_decryption: bool,
    pub size: usize,
}

impl Env {
    pub fn split_off(&mut self) -> Option<BenchOptions> {
        if self.sizes.is_empty() {
            return None;
        }

        let options = BenchOptions {
            defer_decryption: self.defer_decryption,
            size: self.sizes.pop_front().unwrap(),
        };

        Some(options)
    }
}

pub fn parse_env() -> Env {
    todo!()
}
