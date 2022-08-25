use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ctr::cipher::{generic_array::GenericArray, IvSizeUser, KeyIvInit, KeySizeUser, StreamCipher};
use itertools::Itertools;
use rand_core::{CryptoRng, RngCore};

pub mod gen;

// We use AES-CTR for our encryption, with a fixed nonce
const CIPHER_NONCE: &[u8] = b"arith label enc ";
type Enc = ctr::Ctr64LE<aes::Aes128>;
type EncNonce = GenericArray<u8, <Enc as IvSizeUser>::IvSize>;
type EncKey = GenericArray<u8, <Enc as KeySizeUser>::KeySize>;

pub type NonArithLabel = [u8; 16];
pub type EncryptedArithLabel = Vec<u8>;

// Helper function: returns the select bit of our labels, which is the LSB
fn get_select_bit(label: &NonArithLabel) -> bool {
    (label[15] & 0b00000001) != 0
}

// Uniformly generates a full set of arithmetic labels, with the structure that `labelibit1 =
// labelibit0 + Δ` for some global (uniformly sampled) `Δ`.
//
// Input: `num_wires` is the number of output wires that need to be generated
//
// Outputs: Returns `Δ` and an iterator for the full set of arithmetic labels. There are `2 *
// num_wires` labels in this iterator, with the ordering `[label1bit0, label1bit1, label2bit0,
// label2bit1, ..., ]`.
pub fn gen_arith_labels<F, R>(mut rng: R, num_wires: usize) -> (F, impl Iterator<Item = F>)
where
    F: Field,
    R: RngCore + CryptoRng,
{
    // First sample a random Δ
    let delta = F::rand(&mut rng);
    // Generate the labels
    let labels = (0..num_wires).flat_map(move |_| {
        // Make the two labels, bit0, and bit1 = bit0 + Δ
        let bit0_label = F::rand(&mut rng);
        let bit1_label = bit0_label + delta;
        [bit0_label, bit1_label]
    });

    (delta, labels)
}

/// Uses the given non-arithmetic labels to encrypt the given arithmetic labels.
///
/// Inputs: The non-arithmetic labels are assumed to have the LSB be the point-and-permute select
/// bit. The input iterators MUST be the same length.
///
/// Output: Each ciphertext pair in the output is ordered so that the LSB of the 0 bit nonarith
/// label points to the position of the 0 bit arith label.
pub fn encrypt_and_sort_arith_labels<'a, F: Field>(
    nonarith_labels: impl IntoIterator<Item = NonArithLabel>,
    arith_labels: impl IntoIterator<Item = F>,
) -> impl Iterator<Item = EncryptedArithLabel> {
    // Instantiate the global nonce
    let nonce = EncNonce::from_slice(CIPHER_NONCE);

    // Go through every (key, plaintext) pair and encrypt
    nonarith_labels
        .into_iter()
        .zip(arith_labels.into_iter())
        .tuples()
        .flat_map(move |((k1, alabel0), (k2, alabel1))| {
            // Get the point-and-permute select bit
            let select_bit = get_select_bit(&k1);

            // Serialize the arithmetic labels
            let mut byte_buf0 = Vec::new();
            let mut byte_buf1 = Vec::new();
            <F as CanonicalSerialize>::serialize(&alabel0, &mut byte_buf0).unwrap();
            <F as CanonicalSerialize>::serialize(&alabel1, &mut byte_buf1).unwrap();

            // Encrypt the serialized labels in place
            let mut cipher1 = {
                let key = EncKey::clone_from_slice(&k1);
                Enc::new(&key, &nonce)
            };
            let mut cipher2 = {
                let key = EncKey::clone_from_slice(&k2);
                Enc::new(&key, &nonce)
            };
            cipher1.apply_keystream(&mut byte_buf0);
            cipher2.apply_keystream(&mut byte_buf1);

            // Rename
            let ct0 = byte_buf0;
            let ct1 = byte_buf1;

            // Use the select bit to sort the ciphertexts
            if select_bit {
                [ct1, ct0]
            } else {
                [ct0, ct1]
            }
        })
}

/// Uses the given non-arithmetic labels to encrypt the given arithmetic labels. The input
/// iterators MUST be the same length.
pub fn decrypt_arith_label<F: Field>(
    non_arith_label: &NonArithLabel,
    ciphertexts: (&EncryptedArithLabel, &EncryptedArithLabel),
) -> Result<F, SerializationError> {
    // Instantiate the global nonce
    let nonce = EncNonce::from_slice(CIPHER_NONCE);
    // Get the point-and-permute select bit
    let select_bit = get_select_bit(non_arith_label);

    let mut cipher = {
        let key = EncKey::clone_from_slice(non_arith_label);
        Enc::new(&key, &nonce)
    };

    // Select the ciphertext via the select bit
    let mut ct = if select_bit {
        ciphertexts.1.clone()
    } else {
        ciphertexts.0.clone()
    };

    // Now decrypt
    cipher.apply_keystream(&mut ct);
    let pt = ct;

    // Deserialize the arithmetic label
    <F as CanonicalDeserialize>::deserialize(pt.as_slice()).map_err(Into::into)
}

/// Decrypts the arithmetic labels in `ciphertexts`, using `non_arith_labels` as the keys.
///
/// Inputs: `ciphertext.len() == 2 * non_arith_labels.len()`. In particular, `non_arith_labels[i]`
/// is used to decrypt either `ciphertexts[2*i]` or `ciphertexts[2*i + 1]`, depending on the select
/// bit.
///
/// Output: The decrypted and deserialized arithmetic labels
pub fn decrypt_arith_labels<F: Field>(
    non_arith_labels: impl IntoIterator<Item = NonArithLabel>,
    ciphertexts: impl IntoIterator<Item = EncryptedArithLabel>,
) -> impl Iterator<Item = Result<F, SerializationError>> {
    // Go through all the ciphertexts and decrypt 1/2 of them
    non_arith_labels
        .into_iter()
        .zip(ciphertexts.into_iter().tuples())
        .map(|(k, (ct0, ct1))| decrypt_arith_label(&k, (&ct0, &ct1)))
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::Rng;

    // Field choice doesn't matter. Let it be the scalar field of BLS12-381
    type F = ark_bls12_381::Fr;

    // Generates `2 * num_wires` labels, ordered as `[label1bit0, label1bit1, label2bit0, ...]`.
    // Each label's LSB is set to a select bit, and the other label in the bit pair is given the
    // flipped select bit value as LSB.
    fn gen_pointandpermute_labels(mut rng: impl Rng, num_wires: usize) -> Vec<NonArithLabel> {
        // Generate the labels and select bits
        (0..num_wires)
            .flat_map(|_| {
                // Generate the labels uniformly
                let mut label0 = {
                    let mut buf = [0u8; 16];
                    rng.fill_bytes(&mut buf);
                    buf
                };
                let mut label1 = {
                    let mut buf = [0u8; 16];
                    rng.fill_bytes(&mut buf);
                    buf
                };

                // Now pick the select bit uniformly and set the LSB of the labels accordingly
                let select_bit: bool = rng.gen();
                if select_bit {
                    label0[15] |= 0b00000001;
                    label1[15] &= 0b11111110;
                } else {
                    label1[15] |= 0b00000001;
                    label0[15] &= 0b11111110;
                }

                [label0, label1]
            })
            .collect()
    }

    #[test]
    fn point_and_permute_correctness() {
        let mut rng = rand::thread_rng();
        let num_wires = 100;

        // Garbler: Generate a full set of arithmetic and nonarithmetic labels
        let nonarith_labels = gen_pointandpermute_labels(&mut rng, num_wires);
        let arith_labels: Vec<_> = gen_arith_labels::<F, _>(&mut rng, num_wires).1.collect();

        // No party does this, but we need to do it for testing: Generate a random plaintext and
        // the corresponding nonarithmetic labels. The labels are what the evaluator has before she
        // begins decrypting arithmetic labels.
        let plaintext: Vec<bool> = (0..num_wires).map(|_| rng.gen()).collect();
        let active_nonarith_labels: Vec<_> = plaintext
            .iter()
            .zip(nonarith_labels.iter().tuples())
            .map(|(&b, (l0, l1))| if b { l1 } else { l0 })
            .cloned()
            .collect();
        let active_arith_labels: Vec<_> = plaintext
            .iter()
            .zip(arith_labels.iter().tuples())
            .map(|(&b, (l0, l1))| if b { l1 } else { l0 })
            .cloned()
            .collect();

        // Garbler: Encrypt and sort (by select bit) all the arith labels, and send them to the
        // evaluator
        let encrypted_arith_labels: Vec<_> =
            encrypt_and_sort_arith_labels(nonarith_labels.clone(), arith_labels.clone()).collect();

        // Evaluator: Use the active nonarithmetic labels to decrypt the shuffled arithmetic labels
        let computed_arith_labels =
            decrypt_arith_labels::<F>(active_nonarith_labels, encrypted_arith_labels)
                .collect::<Result<Vec<_>, _>>()
                .unwrap();

        // Assert that the derived labels are the expected ones
        assert_eq!(computed_arith_labels, active_arith_labels);
    }
}
