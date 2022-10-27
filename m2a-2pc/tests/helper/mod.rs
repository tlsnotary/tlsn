use mpc_core::Block;

pub fn u128_to_bool(a: u128) -> [bool; 128] {
    let mut out = [false; 128];
    for (k, item) in out.iter_mut().enumerate() {
        *item = (a >> k & 1) == 1
    }
    out
}

pub fn interleave_to_blocks(values: ([u128; 128], [u128; 128])) -> Vec<[Block; 2]> {
    let mut out = vec![];
    for (first, second) in values.0.into_iter().zip(values.1.into_iter()) {
        out.push([Block::new(first), Block::new(second)]);
    }
    out
}
