use cipher::{consts::U16, BlockCipher, BlockEncrypt};

use crate::{
    block::{Block, SELECT_MASK},
    garble::{circuit::EncryptedGate, label::ActiveInputLabelsSet, Error, LabelError, WireLabel},
};
use mpc_circuits::{Circuit, Gate};

/// Evaluates half-gate garbled AND gate
#[inline]
pub(crate) fn and_gate<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &C,
    x: &WireLabel,
    y: &WireLabel,
    zref: usize,
    encrypted_gate: &[Block; 2],
    gid: usize,
) -> WireLabel {
    let s_a = x.as_ref().lsb();
    let s_b = y.as_ref().lsb();

    let j = gid;
    let k = gid + 1;

    let hx = x.as_ref().hash_tweak(cipher, j);
    let hy = y.as_ref().hash_tweak(cipher, k);

    let w_g = hx ^ (encrypted_gate[0] & SELECT_MASK[s_a]);
    let w_e = hy ^ (SELECT_MASK[s_b] & (encrypted_gate[1] ^ *x.as_ref()));

    WireLabel::new(zref, w_g ^ w_e)
}

/// Evaluates half-gate garbled XOR gate
#[inline]
pub(crate) fn xor_gate(x: &WireLabel, y: &WireLabel, zref: usize) -> WireLabel {
    WireLabel::new(zref, *x.as_ref() ^ *y.as_ref())
}

/// Evaluates a garbled circuit using [`SanitizedInputLabels`].
pub fn evaluate<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &C,
    circ: &Circuit,
    input_labels: ActiveInputLabelsSet,
    encrypted_gates: &[EncryptedGate],
) -> Result<Vec<WireLabel>, Error> {
    let mut labels: Vec<Option<WireLabel>> = vec![None; circ.len()];

    // Insert input labels
    input_labels.iter().for_each(|input_labels| {
        input_labels
            .iter()
            .for_each(|label| labels[label.id()] = Some(label))
    });

    let mut tid = 0;
    let mut gid = 1;
    for gate in circ.gates() {
        match *gate {
            Gate::Inv { xref, zref, .. } => {
                let x = labels[xref].ok_or(LabelError::UninitializedLabel(xref))?;
                labels[zref] = Some(x);
            }
            Gate::Xor {
                xref, yref, zref, ..
            } => {
                let x = labels[xref].ok_or(LabelError::UninitializedLabel(xref))?;
                let y = labels[yref].ok_or(LabelError::UninitializedLabel(yref))?;
                let z = xor_gate(&x, &y, zref);
                labels[zref] = Some(z);
            }
            Gate::And {
                xref, yref, zref, ..
            } => {
                let x = labels[xref].ok_or(LabelError::UninitializedLabel(xref))?;
                let y = labels[yref].ok_or(LabelError::UninitializedLabel(yref))?;
                let z = and_gate(cipher, &x, &y, zref, encrypted_gates[tid].as_ref(), gid);
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
