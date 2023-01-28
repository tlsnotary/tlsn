use mpc_aio::protocol::garble::exec::{
    deap::{DEAPExecute, DEAPVerify},
    dual::DEExecute,
};
use mpc_circuits::{Value, WireGroup};
use mpc_core::garble::{ActiveEncodedInput, FullInputSet, Label, LabelPair};

use crate::{
    cipher::{CtrCircuit, CtrShareCircuit},
    BlindBlockTranscript, BlockTranscript, StreamCipherError,
};

pub async fn leader_apply_key_block<C: CtrCircuit, DP: DEAPExecute>(
    leader: DP,
    gen_labels: FullInputSet,
    cached_labels: Vec<ActiveEncodedInput>,
    text: Vec<u8>,
    mut explicit_nonce: Vec<u8>,
    ctr: u32,
) -> Result<(BlockTranscript, Box<dyn DEAPVerify>), StreamCipherError> {
    let cipher = C::default();

    let mut input_text = text.clone();
    input_text.resize(C::BLOCK_SIZE, 0);

    if C::IS_REVERSED {
        input_text.reverse();
        explicit_nonce.reverse();
    }

    let input_text = cipher
        .text()
        .to_value(input_text)
        .expect("Block size should match cipher");
    let input_nonce = cipher
        .nonce()
        .to_value(explicit_nonce)
        .expect("Nonce length should match cipher");
    let input_ctr = cipher
        .counter()
        .to_value(ctr)
        .expect("Counter size should match cipher");

    let gen_inputs = vec![input_text.clone(), input_nonce, input_ctr];
    let ot_send_inputs = vec![];
    let ot_receive_inputs = vec![input_text];

    let (outputs, summary, leader) = leader
        .execute_and_summarize(
            gen_labels,
            gen_inputs,
            ot_send_inputs,
            ot_receive_inputs,
            cached_labels,
        )
        .await?;

    let leader = Box::new(leader);

    let mut text_labels = summary
        .input_labels()
        .get(cipher.text().index())
        .expect("Text labels should be present")
        .iter()
        .collect::<Vec<Label>>();

    let Value::Bytes(mut output_text) = outputs[0].value().clone() else {
        panic!();
    };

    if C::IS_REVERSED {
        output_text.reverse();
    }

    text_labels.truncate(text.len() * 8);
    output_text.truncate(text.len());

    let transcript = BlockTranscript::new(text, text_labels, output_text, ctr);

    Ok((transcript, leader))
}

pub async fn follower_apply_key_block<C: CtrCircuit, DP: DEAPExecute>(
    follower: DP,
    gen_labels: FullInputSet,
    cached_labels: Vec<ActiveEncodedInput>,
    len: usize,
    mut explicit_nonce: Vec<u8>,
    ctr: u32,
) -> Result<(BlindBlockTranscript, Box<dyn DEAPVerify>), StreamCipherError> {
    let cipher = C::default();

    if C::IS_REVERSED {
        explicit_nonce.reverse();
    }

    let input_text = cipher.text();
    let input_nonce = cipher
        .nonce()
        .to_value(explicit_nonce)
        .expect("Nonce length should match cipher");
    let input_ctr = cipher
        .counter()
        .to_value(ctr)
        .expect("Counter size should match cipher");

    let gen_inputs = vec![input_nonce, input_ctr];
    let ot_send_inputs = vec![input_text];
    let ot_receive_inputs = vec![];

    let (outputs, follower) = follower
        .execute(
            gen_labels.clone(),
            gen_inputs,
            ot_send_inputs,
            ot_receive_inputs,
            cached_labels,
        )
        .await?;

    let follower = Box::new(follower);

    let Value::Bytes(mut output_text) = outputs[0].value().clone() else {
        panic!();
    };

    let mut text_labels = gen_labels
        .get(cipher.text().index())
        .expect("Text labels should be present")
        .iter()
        .collect::<Vec<LabelPair>>();

    if C::IS_REVERSED {
        output_text.reverse();
    }

    text_labels.truncate(len * 8);
    output_text.truncate(len);

    let transcript = BlindBlockTranscript::new(len, text_labels, output_text, ctr);

    Ok((transcript, follower))
}

pub async fn leader_share_key_block<C: CtrShareCircuit, DE: DEExecute>(
    leader: DE,
    gen_labels: FullInputSet,
    cached_labels: Vec<ActiveEncodedInput>,
    mut mask: Vec<u8>,
    mut explicit_nonce: Vec<u8>,
    ctr: u32,
) -> Result<Vec<u8>, StreamCipherError> {
    let cipher = C::default();

    if C::IS_REVERSED {
        mask.reverse();
        explicit_nonce.reverse();
    }

    let input_mask_0 = cipher
        .mask_0()
        .to_value(mask.clone())
        .expect("Block size should match cipher");
    let input_mask_1 = cipher.mask_1();
    let input_nonce = cipher
        .nonce()
        .to_value(explicit_nonce)
        .expect("Nonce length should match cipher");
    let input_ctr = cipher
        .counter()
        .to_value(ctr)
        .expect("Counter size should match cipher");

    let gen_inputs = vec![input_mask_0.clone(), input_nonce, input_ctr];
    let ot_send_inputs = vec![input_mask_1];
    let ot_receive_inputs = vec![input_mask_0];

    let output = leader
        .execute(
            gen_labels,
            gen_inputs,
            ot_send_inputs,
            ot_receive_inputs,
            cached_labels,
        )
        .await?;

    let Value::Bytes(masked_key_block) = output[0].value().clone() else {
        panic!();
    };

    // Leader share: KEY_BLOCK + MASK_1
    // Follower share: MASK_1
    let mut share = masked_key_block
        .into_iter()
        .zip(mask.into_iter())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<_>>();

    if C::IS_REVERSED {
        share.reverse();
    }

    Ok(share)
}

pub async fn follower_share_key_block<C: CtrShareCircuit, DE: DEExecute>(
    follower: DE,
    gen_labels: FullInputSet,
    cached_labels: Vec<ActiveEncodedInput>,
    mut mask: Vec<u8>,
    mut explicit_nonce: Vec<u8>,
    ctr: u32,
) -> Result<Vec<u8>, StreamCipherError> {
    let cipher = C::default();

    if C::IS_REVERSED {
        mask.reverse();
        explicit_nonce.reverse();
    }

    let input_mask_0 = cipher.mask_0();
    let input_mask_1 = cipher
        .mask_1()
        .to_value(mask.clone())
        .expect("Block size should match cipher");
    let input_nonce = cipher
        .nonce()
        .to_value(explicit_nonce)
        .expect("Nonce length should match cipher");
    let input_ctr = cipher
        .counter()
        .to_value(ctr)
        .expect("Counter size should match cipher");

    let gen_inputs = vec![input_mask_1.clone(), input_nonce, input_ctr];
    let ot_send_inputs = vec![input_mask_0];
    let ot_receive_inputs = vec![input_mask_1];

    _ = follower
        .execute(
            gen_labels,
            gen_inputs,
            ot_send_inputs,
            ot_receive_inputs,
            cached_labels,
        )
        .await?;

    // Leader share: KEY_BLOCK + MASK_1
    // Follower share: MASK_1
    let mut share = mask;

    if C::IS_REVERSED {
        share.reverse();
    }

    Ok(share)
}
