use homomorph::gf2_128::core::MaskedPartialValue;
use mpc_core::Block;

pub fn u128_to_bool(a: u128) -> [bool; 128] {
    let mut out = [false; 128];
    for (k, item) in out.iter_mut().enumerate() {
        *item = (a >> k & 1) == 1
    }
    out
}

pub fn interleave_to_blocks(values: MaskedPartialValue) -> Vec<[Block; 2]> {
    let mut out = vec![];
    for (first, second) in values.0.iter().zip(values.1.iter()) {
        out.push([Block::new(*first), Block::new(*second)]);
    }
    out
}
