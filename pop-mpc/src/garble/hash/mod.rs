pub mod aes;

use crate::block::Block;

pub trait WireLabelHasher {
    fn hash(&self, label: Block, gid: usize) -> Block;

    //fn hash_many(&mut self, labels: Vec<Block>, gids: Vec<usize>) -> Vec<Block>;
}
