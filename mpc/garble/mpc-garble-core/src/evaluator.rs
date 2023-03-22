use cipher::{consts::U16, BlockCipher, BlockEncrypt};

use crate::{circuit::EncryptedGate, label::ActiveInputSet, EncodingError, Error, Label};
use mpc_circuits::{Circuit, Gate, WireGroup};
use mpc_core::Block;

/// Evaluates half-gate garbled AND gate
#[inline]
pub(crate) fn and_gate<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &C,
    x: &Label,
    y: &Label,
    encrypted_gate: &[Block; 2],
    gid: usize,
) -> Label {
    let x = x.into_inner();
    let y = y.into_inner();

    let s_a = x.lsb();
    let s_b = y.lsb();

    let j = gid;
    let k = gid + 1;

    let hx = x.hash_tweak(cipher, j);
    let hy = y.hash_tweak(cipher, k);

    let w_g = hx ^ (encrypted_gate[0] & Block::SELECT_MASK[s_a]);
    let w_e = hy ^ (Block::SELECT_MASK[s_b] & (encrypted_gate[1] ^ x));

    Label::new(w_g ^ w_e)
}

/// Evaluates half-gate garbled XOR gate
#[inline]
pub(crate) fn xor_gate(x: &Label, y: &Label) -> Label {
    *x ^ *y
}

/// Evaluates a garbled circuit using [`SanitizedInputLabels`].
pub fn evaluate<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &C,
    circ: &Circuit,
    input_labels: ActiveInputSet,
    encrypted_gates: &[EncryptedGate],
) -> Result<Vec<Label>, Error> {
    let mut labels: Vec<Option<Label>> = vec![None; circ.len()];

    // Insert input labels
    input_labels.iter().for_each(|input_labels| {
        input_labels
            .iter()
            .zip(input_labels.wires())
            .for_each(|(label, id)| labels[*id] = Some(label))
    });

    let mut tid = 0;
    let mut gid = 1;
    for gate in circ.gates() {
        match *gate {
            Gate::Inv { xref, zref, .. } => {
                let x = labels[xref].ok_or(EncodingError::UninitializedLabel(xref))?;
                labels[zref] = Some(x);
            }
            Gate::Xor {
                xref, yref, zref, ..
            } => {
                let x = labels[xref].ok_or(EncodingError::UninitializedLabel(xref))?;
                let y = labels[yref].ok_or(EncodingError::UninitializedLabel(yref))?;
                let z = xor_gate(&x, &y);
                labels[zref] = Some(z);
            }
            Gate::And {
                xref, yref, zref, ..
            } => {
                let x = labels[xref].ok_or(EncodingError::UninitializedLabel(xref))?;
                let y = labels[yref].ok_or(EncodingError::UninitializedLabel(yref))?;
                let z = and_gate(cipher, &x, &y, encrypted_gates[tid].as_ref(), gid);
                labels[zref] = Some(z);
                tid += 1;
                gid += 2;
            }
        };
    }

    Ok(labels
        .into_iter()
        .map(|label| label.expect("wire label was not initialized"))
        .collect())
}
