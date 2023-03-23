use cipher::{consts::U16, BlockCipher, BlockEncrypt};

use crate::{
    circuit::EncryptedGate, label::FullInputSet, Delta, EncodingError, Error, Label, LabelPair,
};
use mpc_circuits::{Circuit, Gate, WireGroup};
use mpc_core::Block;

/// Computes half-gate garbled AND gate
#[inline]
pub(crate) fn and_gate<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    c: &C,
    x: &LabelPair,
    y: &LabelPair,
    delta: Delta,
    gid: usize,
) -> (LabelPair, EncryptedGate) {
    let delta = delta.into_inner();
    let x_0 = x.low().into_inner();
    let x_1 = x.high().into_inner();
    let y_0 = y.low().into_inner();
    let y_1 = y.high().into_inner();

    let p_a = x_0.lsb();
    let p_b = y_0.lsb();
    let j = gid;
    let k = gid + 1;

    let hx_0 = x_0.hash_tweak(c, j);
    let hy_0 = y_0.hash_tweak(c, k);

    // Garbled row of generator half-gate
    let t_g = hx_0 ^ x_1.hash_tweak(c, j) ^ (Block::SELECT_MASK[p_b] & delta);
    let w_g = hx_0 ^ (Block::SELECT_MASK[p_a] & t_g);

    // Garbled row of evaluator half-gate
    let t_e = hy_0 ^ y_1.hash_tweak(c, k) ^ x_0;
    let w_e = hy_0 ^ (Block::SELECT_MASK[p_b] & (t_e ^ x_0));

    let z_0 = w_g ^ w_e;

    (
        LabelPair::new(Label::new(z_0), Label::new(z_0 ^ delta)),
        EncryptedGate::new([t_g, t_e]),
    )
}

/// Computes half-gate garbled XOR gate
#[inline]
pub(crate) fn xor_gate(x: &LabelPair, y: &LabelPair, delta: Delta) -> LabelPair {
    let z_0 = x.low() ^ y.low();
    LabelPair::new(z_0, z_0 ^ delta)
}

/// Garbles a circuit using the provided input labels and delta
pub fn garble<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &C,
    circ: &Circuit,
    input_labels: FullInputSet,
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
                let x = labels[xref].ok_or(EncodingError::UninitializedLabel(xref))?;
                labels[zref] = Some(LabelPair::new(x.high(), x.low()));
            }
            Gate::Xor {
                xref, yref, zref, ..
            } => {
                let x = labels[xref].ok_or(EncodingError::UninitializedLabel(xref))?;
                let y = labels[yref].ok_or(EncodingError::UninitializedLabel(yref))?;
                let z = xor_gate(&x, &y, delta);
                labels[zref] = Some(z);
            }
            Gate::And {
                xref, yref, zref, ..
            } => {
                let x = labels[xref].ok_or(EncodingError::UninitializedLabel(xref))?;
                let y = labels[yref].ok_or(EncodingError::UninitializedLabel(yref))?;
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
