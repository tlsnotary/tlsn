use crate::block::Block;
use rand::rngs::ThreadRng;
use rand::{thread_rng, CryptoRng, Rng as RandRng};

pub struct Rng {
    rng: ThreadRng,
}

pub trait RandomBlock {
    fn random_block(&mut self) -> Block;
}

impl Rng {
    pub fn new() -> Self {
        Self { rng: thread_rng() }
    }
}

impl RandomBlock for Rng {
    fn random_block(&mut self) -> Block {
        Block::new(self.rng.gen())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
