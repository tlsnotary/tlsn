use cipher::{consts::U16, BlockCipher, BlockEncrypt};

use crate::block::{Block, SELECT_MASK};
use crate::garble::Error;
use mpc_circuits::{Circuit, Gate};

use super::circuit::BinaryLabel;
use super::EncryptedGate;

/// Evaluates AND gate
#[inline]
pub(crate) fn and_gate<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &C,
    x: &Block,
    y: &Block,
    encrypted_gate: &[Block; 2],
    gid: usize,
) -> Block {
    let s_a = x.lsb();
    let s_b = y.lsb();

    let j = gid;
    let k = gid + 1;

    let hx = x.hash_tweak(cipher, j);
    let hy = y.hash_tweak(cipher, k);

    let w_g = hx ^ (encrypted_gate[0] & SELECT_MASK[s_a]);
    let w_e = hy ^ (SELECT_MASK[s_b] & (encrypted_gate[1] ^ *x));

    w_g ^ w_e
}

/// Evaluates XOR gate
#[inline]
pub(crate) fn xor_gate(x: &Block, y: &Block) -> Block {
    *x ^ *y
}

/// Evaluates INV gate
#[inline]
pub(crate) fn inv_gate(x: &Block, public_label: &Block) -> Block {
    *x ^ *public_label
}

pub fn evaluate<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &C,
    circ: &Circuit,
    input_labels: &[BinaryLabel],
    public_labels: &[BinaryLabel; 2],
    encrypted_gates: &[EncryptedGate],
) -> Result<Vec<Block>, Error> {
    let mut labels: Vec<Option<Block>> = vec![None; circ.len()];
    let public_labels = [*public_labels[0].value(), *public_labels[1].value()];

    // Insert input labels
    for (labels, label) in labels.iter_mut().zip(input_labels) {
        *labels = Some(*label.value())
    }

    let mut tid = 0;
    let mut gid = 1;
    for gate in circ.gates() {
        match *gate {
            Gate::Inv { xref, zref, .. } => {
                let x = labels[xref].ok_or(Error::UninitializedLabel(xref))?;
                let z = inv_gate(&x, &public_labels[1]);
                labels[zref] = Some(z);
            }
            Gate::Xor {
                xref, yref, zref, ..
            } => {
                let x = labels[xref].ok_or(Error::UninitializedLabel(xref))?;
                let y = labels[yref].ok_or(Error::UninitializedLabel(yref))?;
                let z = xor_gate(&x, &y);
                labels[zref] = Some(z);
            }
            Gate::And {
                xref, yref, zref, ..
            } => {
                let x = labels[xref].ok_or(Error::UninitializedLabel(xref))?;
                let y = labels[yref].ok_or(Error::UninitializedLabel(yref))?;
                let z = and_gate(cipher, &x, &y, &encrypted_gates[tid].inner(), gid);
                labels[zref] = Some(z);
                tid += 1;
                gid += 2;
            }
        };
    }

    let outputs = labels
        .drain(circ.len() - circ.output_len()..)
        .map(|label| label.unwrap())
        .collect();

    Ok(outputs)
}
