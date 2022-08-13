use cipher::{consts::U16, BlockCipher, BlockEncrypt};
use std::sync::Arc;

use crate::{
    block::SELECT_MASK,
    garble::{Delta, EncryptedGate, Error, FullGarbledCircuit, InputLabels, WireLabelPair},
};
use mpc_circuits::{Circuit, Gate};

/// Computes garbled AND gate
#[inline]
pub(crate) fn and_gate<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    c: &C,
    x: &WireLabelPair,
    y: &WireLabelPair,
    zref: usize,
    delta: Delta,
    gid: usize,
) -> (WireLabelPair, EncryptedGate) {
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
    let t_e = hy_0 ^ y.high().hash_tweak(c, k) ^ *x.low();
    let w_e = hy_0 ^ (SELECT_MASK[p_b] & (t_e ^ *x.low()));

    let z_0 = w_g ^ w_e;

    (
        WireLabelPair::new(zref, z_0, z_0 ^ *delta),
        EncryptedGate::new([t_g, t_e]),
    )
}

/// Computes garbled XOR gate
#[inline]
pub(crate) fn xor_gate(
    x: &WireLabelPair,
    y: &WireLabelPair,
    zref: usize,
    delta: Delta,
) -> WireLabelPair {
    let z_0 = *x.low() ^ *y.low();
    WireLabelPair::new(zref, z_0, z_0 ^ *delta)
}

/// Garbles a circuit using the provided input labels and delta
pub fn garble<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &C,
    circ: &Circuit,
    delta: Delta,
    input_labels: &[WireLabelPair],
) -> Result<(Vec<WireLabelPair>, Vec<EncryptedGate>), Error> {
    let mut encrypted_gates: Vec<EncryptedGate> = Vec::with_capacity(circ.and_count());
    // Every wire label pair for the circuit
    let mut labels: Vec<Option<WireLabelPair>> = vec![None; circ.len()];

    // Insert input labels
    for pair in input_labels {
        labels[pair.id()] = Some(*pair)
    }

    let mut gid = 1;
    for gate in circ.gates() {
        match *gate {
            Gate::Inv { xref, zref, .. } => {
                let x = labels[xref].ok_or(Error::UninitializedLabel(xref))?;
                labels[zref] = Some(WireLabelPair::new(zref, *x.high(), *x.low()));
            }
            Gate::Xor {
                xref, yref, zref, ..
            } => {
                let x = labels[xref].ok_or(Error::UninitializedLabel(xref))?;
                let y = labels[yref].ok_or(Error::UninitializedLabel(yref))?;
                let z = xor_gate(&x, &y, zref, delta);
                labels[zref] = Some(z);
            }
            Gate::And {
                xref, yref, zref, ..
            } => {
                let x = labels[xref].ok_or(Error::UninitializedLabel(xref))?;
                let y = labels[yref].ok_or(Error::UninitializedLabel(yref))?;
                let (z, t) = and_gate(cipher, &x, &y, zref, delta, gid);
                encrypted_gates.push(t);
                labels[zref] = Some(z);
                gid += 2;
            }
        };
    }

    let labels: Vec<WireLabelPair> = labels
        .into_iter()
        .map(|pair| pair.expect("wire label was not initialized"))
        .collect();

    Ok((labels, encrypted_gates))
}

/// Generate a garbled circuit with the provided input labels and delta.
pub fn generate_garbled_circuit<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &C,
    circ: Arc<Circuit>,
    delta: Delta,
    input_labels: &[InputLabels<WireLabelPair>],
) -> Result<FullGarbledCircuit, Error> {
    let input_labels: Vec<WireLabelPair> = input_labels
        .iter()
        .map(|pair| pair.as_ref())
        .flatten()
        .copied()
        .collect();
    let (labels, encrypted_gates) = garble(cipher, &circ, delta, &input_labels)?;
    Ok(FullGarbledCircuit::new(
        circ,
        labels,
        encrypted_gates,
        delta,
    ))
}

#[cfg(test)]
mod tests {
    use crate::garble::generate_label_pairs;

    use super::*;
    use aes::{
        cipher::{generic_array::GenericArray, NewBlockCipher},
        Aes128,
    };
    use mpc_circuits::AES_128_REVERSE;
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    #[test]
    fn test_uninitialized_label() {
        let cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
        let mut rng = ChaCha12Rng::from_entropy();
        let circ = Arc::new(Circuit::load_bytes(AES_128_REVERSE).unwrap());

        let (input_labels, delta) = generate_label_pairs(&mut rng, None, circ.input_len() - 1, 0);

        let result = garble(&cipher, &circ, delta, &input_labels);
        assert!(matches!(result, Err(Error::UninitializedLabel(_))));
    }
}
