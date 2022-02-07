use crate::block::Block;
use rand::rngs::ThreadRng;
use rand::{thread_rng, CryptoRng, Rng};

pub struct RandPrg {
    rng: ThreadRng,
}

pub trait Prg {
    fn random_block(&mut self) -> Block;
}

impl RandPrg {
    pub fn new() -> Self {
        Self { rng: thread_rng() }
    }
}

impl Prg for RandPrg {
    fn random_block(&mut self) -> Block {
        Block::new(self.rng.gen())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
