use mpc_core::Block;

pub fn ot_mock_batch(envelopes: Vec<[Block; 2]>, choices: &[bool]) -> Vec<Block> {
    let mut out: Vec<Block> = vec![];

    for (envelope, choice) in envelopes.into_iter().zip(choices.iter()) {
        out.push(ot_mock(envelope, *choice));
    }
    out
}

fn ot_mock(envelope: [Block; 2], choice: bool) -> Block {
    if choice {
        envelope[1]
    } else {
        envelope[0]
    }
}
