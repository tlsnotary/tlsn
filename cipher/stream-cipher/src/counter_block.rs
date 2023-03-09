use mpc_aio::protocol::garble::exec::dual::DEExecute;
use mpc_circuits::{Value, WireGroup};
use mpc_core::garble::{exec::dual::DESummary, ActiveEncodedInput, FullInputSet};
use rand::RngCore;

use crate::{
    cipher::{CtrCircuit, CtrShareCircuit},
    Role, StreamCipherError,
};

#[derive(Debug)]
pub struct KeyBlockLabels {
    pub(crate) gen_labels: FullInputSet,
    pub(crate) active_key_labels: ActiveEncodedInput,
    pub(crate) active_iv_labels: ActiveEncodedInput,
}

/// Applies a key block to a block of text.
///
/// * `de` - The dual execution instance to use
/// * `labels` - The input labels for the key block circuit
/// * `text` - The input text to apply the key block to.
/// * `explicit_nonce` - The explicit nonce to use for the key block
/// * `ctr` - The counter value to use for the key block
/// * `private` - Whether the input text is private.
///
/// # Privacy Modes
///
/// If the `text` is `None`, then the input text is private and provided by the
/// other party (blind mode). The input labels for it will be sent via OT.
///
/// If the `text` is `Some` and `private` is `true`, then the input text is private
/// and provided by us. The input labels for it will be received via OT.
///
/// If the `text` is `Some` and `private` is `false`, then the input text is public
/// and is provided by both parties. In which case, no OT is required and the execution
/// will fail if the input text does not match.
pub(crate) async fn apply_key_block<C: CtrCircuit, DE: DEExecute>(
    de: DE,
    labels: KeyBlockLabels,
    text: Option<Vec<u8>>,
    explicit_nonce: Vec<u8>,
    ctr: u32,
    private: bool,
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

    let (gen_inputs, ot_send_inputs, ot_receive_inputs) = if let Some(text) = text {
        let input_text = cipher
            .input_text()
            .to_value(text)
            .expect("Block size should match cipher");

        // If we have the input text, we provide it as a generator input
        let gen_inputs = vec![input_text.clone(), input_nonce, input_ctr];
        // We don't send any inputs via OT when we already have the input text
        let ot_send_inputs = vec![];
        // If we have the input text and it is private, we must receive the labels
        // for it via OT
        let ot_receive_inputs = if private { vec![input_text] } else { vec![] };

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

    let Value::Bytes(output_text) = outputs[0].value().clone() else {
        panic!("Output 0 should be text bytes");
    };

    Ok((output_text, summary))
}

/// Shares a key block between two parties.
///
/// * `role` - The role of the current party
/// * `de` - The dual execution instance to use
/// * `labels` - The input labels for the key block circuit
/// * `explicit_nonce` - The explicit nonce to use for the key block
/// * `ctr` - The counter value to use for the key block
///
/// # Shares
///
/// The key block is shared between the two parties, where each party generates
/// a random mask which is applied to the key block.
///
/// The Leader removes their mask from the resulting masked key block, so they hold:
///
/// Leader share: KEY_BLOCK ⊕ FOLLOWER_MASK
///
/// The Follower simply uses their mask as their share of the key block:
///
/// Follower share: FOLLOWER_MASK
///
/// Now both parties hold additive shares of the key block.
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

    // Leader share: KEY_BLOCK ⊕ FOLLOWER_MASK
    // Follower share: FOLLOWER_MASK
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
