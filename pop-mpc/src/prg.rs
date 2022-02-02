use crate::block::Block;
use rand::rngs::ThreadRng;
use rand::{thread_rng, CryptoRng, Rng};

pub struct RandPRG {
    rng: ThreadRng,
}

pub trait PRG {
    fn random_block(&mut self) -> Block;
}

impl RandPRG {
    pub fn new() -> Self {
        Self { rng: thread_rng() }
    }
}

impl PRG for RandPRG {
    fn random_block(&mut self) -> Block {
        Block::new(self.rng.gen())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
