use cipher::{consts::U16, BlockCipher, BlockEncrypt};
use std::sync::Arc;

use crate::block::{Block, SELECT_MASK};
use crate::garble::Error;
use mpc_circuits::{Circuit, Gate};

use super::circuit::{BinaryLabel, EncryptedGate};
use super::FullGarbledCircuit;

/// Computes garbled AND gate
#[inline]
pub(crate) fn and_gate<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    c: &C,
    x: &[Block; 2],
    y: &[Block; 2],
    delta: &Block,
    gid: usize,
) -> ([Block; 2], [Block; 2]) {
    let p_a = x[0].lsb();
    let p_b = y[0].lsb();
    let j = gid;
    let k = gid + 1;

    let hx_0 = x[0].hash_tweak(c, j);
    let hy_0 = y[0].hash_tweak(c, k);

    // Garbled row of generator half-gate
    let t_g = hx_0 ^ x[1].hash_tweak(c, j) ^ (SELECT_MASK[p_b] & *delta);
    let w_g = hx_0 ^ (SELECT_MASK[p_a] & t_g);

    // Garbled row of evaluator half-gate
    let t_e = hy_0 ^ y[1].hash_tweak(c, k) ^ x[0];
    let w_e = hy_0 ^ (SELECT_MASK[p_b] & (t_e ^ x[0]));

    let z_0 = w_g ^ w_e;
    // The gates output wire labels
    let z = [z_0, z_0 ^ *delta];

    (z, [t_g, t_e])
}

/// Computes garbled XOR gate
#[inline]
pub(crate) fn xor_gate(x: &[Block; 2], y: &[Block; 2], delta: &Block) -> [Block; 2] {
    let z_0 = x[0] ^ y[0];
    [z_0, z_0 ^ *delta]
}

/// Computes garbled INV gate
#[inline]
pub(crate) fn inv_gate(x: &[Block; 2], public_labels: &[Block; 2], delta: &Block) -> [Block; 2] {
    let z_0 = x[0] ^ public_labels[1];
    [z_0 ^ *delta, z_0]
}

pub fn garble<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &C,
    circ: &Circuit,
    delta: &Block,
    input_labels: &[[BinaryLabel; 2]],
    public_labels: &[BinaryLabel; 2],
) -> Result<(Vec<[BinaryLabel; 2]>, Vec<EncryptedGate>), Error> {
    let mut encrypted_gates: Vec<EncryptedGate> = Vec::with_capacity(circ.and_count());
    // Every wire label pair for the circuit
    let mut labels: Vec<Option<[Block; 2]>> = vec![None; circ.len()];
    let public_labels = [*public_labels[0].as_ref(), *public_labels[1].as_ref()];

    // Insert input labels
    for (labels, pair) in labels.iter_mut().zip(input_labels) {
        *labels = Some([*pair[0].as_ref(), *pair[1].as_ref()])
    }

    let mut gid = 1;
    for gate in circ.gates() {
        match *gate {
            Gate::Inv { xref, zref, .. } => {
                let x = labels[xref].ok_or(Error::UninitializedLabel(xref))?;
                let z = inv_gate(&x, &public_labels, delta);
                labels[zref] = Some(z);
            }
            Gate::Xor {
                xref, yref, zref, ..
            } => {
                let x = labels[xref].ok_or(Error::UninitializedLabel(xref))?;
                let y = labels[yref].ok_or(Error::UninitializedLabel(yref))?;
                let z = xor_gate(&x, &y, delta);
                labels[zref] = Some(z);
            }
            Gate::And {
                xref, yref, zref, ..
            } => {
                let x = labels[xref].ok_or(Error::UninitializedLabel(xref))?;
                let y = labels[yref].ok_or(Error::UninitializedLabel(yref))?;
                let (z, t) = and_gate(cipher, &x, &y, &delta, gid);
                encrypted_gates.push(EncryptedGate::new(t));
                labels[zref] = Some(z);
                gid += 2;
            }
        };
    }

    let wire_labels = labels
        .into_iter()
        .enumerate()
        .map(|(id, pair)| {
            let [low, high] = pair.unwrap();
            [BinaryLabel::new(id, low), BinaryLabel::new(id, high)]
        })
        .collect();

    Ok((wire_labels, encrypted_gates))
}

pub fn generate_garbled_circuit<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &C,
    circ: Arc<Circuit>,
    delta: &Block,
    input_labels: &[[BinaryLabel; 2]],
    public_labels: &[BinaryLabel; 2],
) -> Result<FullGarbledCircuit, Error> {
    let (wire_labels, encrypted_gates) = garble(cipher, &circ, delta, input_labels, public_labels)?;
    Ok(FullGarbledCircuit {
        circ,
        wire_labels,
        public_labels: public_labels.clone(),
        encrypted_gates,
        delta: delta.clone(),
    })
}

#[cfg(test)]
mod tests {
    use crate::garble::circuit::{generate_labels, generate_public_labels};

    use super::*;
    use aes::cipher::{generic_array::GenericArray, NewBlockCipher};
    use aes::Aes128;
    use mpc_circuits::AES_128_REVERSE;
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    #[test]
    fn test_uninitialized_label() {
        let cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
        let mut rng = ChaCha12Rng::from_entropy();
        let circ = Arc::new(Circuit::load_bytes(AES_128_REVERSE).unwrap());

        let (input_labels, delta) = generate_labels(&mut rng, None, circ.input_len() - 1, 0);
        let public_labels = generate_public_labels(&mut rng, &delta);

        let result = garble(&cipher, &circ, &delta, &input_labels, &public_labels);
        assert!(matches!(result, Err(Error::UninitializedLabel(_))));
    }
}
