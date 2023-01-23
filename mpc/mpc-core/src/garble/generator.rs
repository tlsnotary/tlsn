use cipher::{consts::U16, BlockCipher, BlockEncrypt};

use crate::{
    block::SELECT_MASK,
    garble::{circuit::EncryptedGate, Delta, Error, LabelError, LabelPair},
};
use mpc_circuits::{Circuit, Gate, WireGroup};

use super::label::FullInputLabelsSet;

/// Computes half-gate garbled AND gate
#[inline]
pub(crate) fn and_gate<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    c: &C,
    x: &LabelPair,
    y: &LabelPair,
    delta: Delta,
    gid: usize,
) -> (LabelPair, EncryptedGate) {
    let p_a = x.low().lsb();
    let p_b = y.low().lsb();
    let j = gid;
    let k = gid + 1;

    let hx_0 = x.low().hash_tweak(c, j);
    let hy_0 = y.low().hash_tweak(c, k);

    // Garbled row of generator half-gate
    let t_g = hx_0 ^ x.high().hash_tweak(c, j) ^ (SELECT_MASK[p_b] & *delta);
    let w_g = hx_0 ^ (SELECT_MASK[p_a] & t_g);

    // Garbled row of evaluator half-gate
    let t_e = hy_0 ^ y.high().hash_tweak(c, k) ^ x.low();
    let w_e = hy_0 ^ (SELECT_MASK[p_b] & (t_e ^ x.low()));

    let z_0 = w_g ^ w_e;

    (
        LabelPair::new(z_0, z_0 ^ *delta),
        EncryptedGate::new([t_g, t_e]),
    )
}

/// Computes half-gate garbled XOR gate
#[inline]
pub(crate) fn xor_gate(x: &LabelPair, y: &LabelPair, delta: Delta) -> LabelPair {
    let z_0 = x.low() ^ y.low();
    LabelPair::new(z_0, z_0 ^ *delta)
}

/// Garbles a circuit using the provided input labels and delta
pub fn garble<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &C,
    circ: &Circuit,
    input_labels: FullInputLabelsSet,
) -> Result<(Vec<LabelPair>, Vec<EncryptedGate>), Error> {
    let mut encrypted_gates: Vec<EncryptedGate> = Vec::with_capacity(circ.and_count());
    // Every wire label pair for the circuit
    let mut labels: Vec<Option<LabelPair>> = vec![None; circ.len()];

    let delta = input_labels.delta();

    // Insert input labels
    input_labels.iter().for_each(|input_labels| {
        input_labels
            .iter()
            .zip(input_labels.wires())
            .for_each(|(label, id)| labels[*id] = Some(label))
    });

    let mut gid = 1;
    for gate in circ.gates() {
        match *gate {
            Gate::Inv { xref, zref, .. } => {
                let x = labels[xref].ok_or(LabelError::UninitializedLabel(xref))?;
                labels[zref] = Some(LabelPair::new(x.high(), x.low()));
            }
            Gate::Xor {
                xref, yref, zref, ..
            } => {
                let x = labels[xref].ok_or(LabelError::UninitializedLabel(xref))?;
                let y = labels[yref].ok_or(LabelError::UninitializedLabel(yref))?;
                let z = xor_gate(&x, &y, delta);
                labels[zref] = Some(z);
            }
            Gate::And {
                xref, yref, zref, ..
            } => {
                let x = labels[xref].ok_or(LabelError::UninitializedLabel(xref))?;
                let y = labels[yref].ok_or(LabelError::UninitializedLabel(yref))?;
                let (z, t) = and_gate(cipher, &x, &y, delta, gid);
                encrypted_gates.push(t);
                labels[zref] = Some(z);
                gid += 2;
            }
        };
    }

    let labels: Vec<LabelPair> = labels
        .into_iter()
        .map(|pair| pair.expect("wire label was not initialized"))
        .collect();

    Ok((labels, encrypted_gates))
}
