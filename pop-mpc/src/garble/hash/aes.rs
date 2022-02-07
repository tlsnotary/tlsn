use super::WireLabelHasher;
use crate::block::Block;
use aes::cipher::{
    generic_array::GenericArray, BlockCipher, BlockDecrypt, BlockEncrypt, NewBlockCipher,
};
use aes::{Aes128, Block as AesBlock, ParBlocks};
use std::convert::TryInto;
use std::ops::BitXor;

pub struct Aes {
    cipher: Aes128,
}

impl Aes {
    pub fn new(key: &[u8; 16]) -> Self {
        Aes {
            cipher: Aes128::new(GenericArray::from_slice(key)),
        }
    }
}

fn xor_blocks(a: AesBlock, b: AesBlock) -> AesBlock {
    a.into_iter().zip(b).map(|(_a, _b)| _a ^ _b).collect()
}

impl WireLabelHasher for Aes {
    /// π(π(x) ⊕ i) ⊕ π(x)
    fn hash(&self, label: Block, gid: usize) -> Block {
        let gid: [u8; 16] = (gid as u128).to_be_bytes();
        let label: [u8; 16] = label.to_be_bytes();

        let mut h1 = AesBlock::from(label);
        self.cipher.encrypt_block(&mut h1);

        let h2 = AesBlock::clone_from_slice(h1.as_slice());
        let mut h2 = h2.into_iter().zip(gid).map(|(a, b)| a ^ b).collect();
        self.cipher.encrypt_block(&mut h2);

        let h3 = AesBlock::clone_from_slice(h2.as_slice());
        let h3: AesBlock = h3.into_iter().zip(h1).map(|(a, b)| a ^ b).collect();

        let b: [u8; 16] = h3
            .as_slice()
            .try_into()
            .expect("Expected array to have length 16");
        let h: u128 = u128::from_be_bytes(b);
        Block::new(h)
    }

    // fn hash_many(&mut self, labels: Vec<Block>, gids: Vec<usize>) -> Vec<Block> {
    //     let gids: Vec<AesBlock> = gids
    //         .into_iter()
    //         .map(|gid| AesBlock::clone_from_slice((gid as u128).to_ne_bytes().as_ref()))
    //         .collect();

    //     // π(x)
    //     let mut h1: ParBlocks = labels
    //         .into_iter()
    //         .map(|label| AesBlock::from(label))
    //         .collect();
    //     self.cipher.encrypt_par_blocks(&mut h1);

    //     // π(π(x) ⊕ i)
    //     let h2: ParBlocks = h1.iter().map(|b| AesBlock::clone_from_slice(b)).collect();
    //     let mut h2: ParBlocks = h2
    //         .into_iter()
    //         .zip(gids)
    //         .map(|(h, gid)| xor_blocks(h, gid))
    //         .collect();
    //     self.cipher.encrypt_par_blocks(&mut h2);

    //     // π(π(x) ⊕ i) ⊕ π(x)
    //     let h: Vec<Block> = h1
    //         .into_iter()
    //         .zip(h2)
    //         .map(|(h1, h2)| {
    //             let h = xor_blocks(h1, h2);
    //             let bytes: [u8; 16] = h.try_into().expect("Expected array to be length 16");
    //             Block::from(bytes)
    //         })
    //         .collect();
    //     h
    // }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes() {
        let key = [0u8; 16];
        let aes = Aes::new(&key);
    }
}
