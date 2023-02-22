use mpc_aio::protocol::garble::exec::dual::DEExecute;
use mpc_circuits::{Value, WireGroup};
use mpc_core::garble::{exec::dual::DESummary, ActiveEncodedInput, FullInputSet};
use rand::RngCore;

use crate::{
    cipher::{CtrCircuit, CtrShareCircuit},
    config::ApplyKeyBlockConfig,
    Role, StreamCipherError,
};

#[derive(Debug)]
pub struct KeyBlockLabels {
    pub(crate) gen_labels: FullInputSet,
    pub(crate) active_key_labels: ActiveEncodedInput,
    pub(crate) active_iv_labels: ActiveEncodedInput,
}

pub(crate) async fn apply_key_block<C: CtrCircuit, DE: DEExecute>(
    config: ApplyKeyBlockConfig,
    de: DE,
    labels: KeyBlockLabels,
    explicit_nonce: Vec<u8>,
    ctr: u32,
) -> Result<(Vec<u8>, DESummary), StreamCipherError> {
    let cipher = C::default();

    let KeyBlockLabels {
        gen_labels,
        active_key_labels: input_key,
        active_iv_labels: input_iv,
    } = labels;

    let input_nonce = cipher
        .nonce()
        .to_value(explicit_nonce)
        .expect("Nonce length should match cipher");
    let input_ctr = cipher
        .counter()
        .to_value(ctr)
        .expect("Counter size should match cipher");

    let mut text = config.get_input_text();

    let (gen_inputs, ot_send_inputs, ot_receive_inputs) = if let Some(text) = text.as_mut() {
        // Pad the text to the block size
        text.resize(C::BLOCK_SIZE, 0);

        let input_text = cipher
            .input_text()
            .to_value(text.clone())
            .expect("Block size should match cipher");

        // If we have the input text, we provide it as a generator input
        let gen_inputs = vec![input_text.clone(), input_nonce, input_ctr];
        // We don't send any inputs via OT when we already have the input text
        let ot_send_inputs = vec![];
        // If we have the input text and it is private, we must receive the labels
        // for it via OT
        let ot_receive_inputs = if config.is_private() {
            vec![input_text]
        } else {
            vec![]
        };

        (gen_inputs, ot_send_inputs, ot_receive_inputs)
    } else {
        // If we don't have the input text (blind), we only provide the nonce and
        // counter as generator inputs
        let gen_inputs = vec![input_nonce, input_ctr];
        // We send the input text labels via OT
        let ot_send_inputs = vec![cipher.input_text()];
        let ot_receive_inputs = vec![];

        (gen_inputs, ot_send_inputs, ot_receive_inputs)
    };

    let cached_labels = vec![input_key, input_iv];

    let (outputs, summary) = de
        .execute_and_summarize(
            gen_labels,
            gen_inputs,
            ot_send_inputs,
            ot_receive_inputs,
            cached_labels,
        )
        .await?;

    let Value::Bytes(mut output_text) = outputs[0].value().clone() else {
        panic!("Output 0 should be text bytes");
    };

    // Strip any padding
    output_text.truncate(config.len());

    Ok((output_text, summary))
}

pub(crate) async fn share_key_block<C: CtrShareCircuit, DE: DEExecute>(
    role: Role,
    de: DE,
    labels: KeyBlockLabels,
    explicit_nonce: Vec<u8>,
    ctr: u32,
) -> Result<Vec<u8>, StreamCipherError> {
    let cipher = C::default();

    let KeyBlockLabels {
        gen_labels,
        active_key_labels: input_key,
        active_iv_labels: input_iv,
    } = labels;

    let mut mask = vec![0u8; C::BLOCK_SIZE];
    rand::thread_rng().fill_bytes(&mut mask);

    let input_nonce = cipher
        .nonce()
        .to_value(explicit_nonce)
        .expect("Nonce length should match cipher");
    let input_ctr = cipher
        .counter()
        .to_value(ctr)
        .expect("Counter size should match cipher");

    let (gen_inputs, ot_send_inputs, ot_receive_inputs) = match role {
        Role::Leader => {
            let input_mask = cipher
                .mask_0()
                .to_value(mask.clone())
                .expect("Mask length should match cipher");

            let gen_inputs = vec![input_nonce, input_ctr, input_mask.clone()];
            let ot_send_inputs = vec![cipher.mask_1()];
            let ot_receive_inputs = vec![input_mask];

            (gen_inputs, ot_send_inputs, ot_receive_inputs)
        }
        Role::Follower => {
            let input_mask = cipher
                .mask_1()
                .to_value(mask.clone())
                .expect("Mask length should match cipher");

            let gen_inputs = vec![input_nonce, input_ctr, input_mask.clone()];
            let ot_send_inputs = vec![cipher.mask_0()];
            let ot_receive_inputs = vec![input_mask];

            (gen_inputs, ot_send_inputs, ot_receive_inputs)
        }
    };

    let cached_labels = vec![input_key, input_iv];

    let output = de
        .execute(
            gen_labels,
            gen_inputs,
            ot_send_inputs,
            ot_receive_inputs,
            cached_labels,
        )
        .await?;

    let Value::Bytes(masked_key_block) = output[0].value().clone() else {
        panic!("Output 0 should be bytes");
    };

    // Leader share: KEY_BLOCK + MASK_1
    // Follower share: MASK_1
    let share = match role {
        Role::Leader => masked_key_block
            .into_iter()
            .zip(mask.into_iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<_>>(),
        Role::Follower => mask,
    };

    Ok(share)
}
