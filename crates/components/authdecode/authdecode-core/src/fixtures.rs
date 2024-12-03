use crate::{
    encodings::{Encoding, FullEncodings},
    mock::{Direction, MockBitIds, MockEncodingProvider},
    prover::CommitmentData,
    SSP,
};
use itybity::ToBits;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

// The size of plaintext in bytes;
#[allow(dead_code)]
const PLAINTEXT_SIZE: usize = 1000;

pub fn commitment_data() -> Vec<CommitmentData<MockBitIds>> {
    let mut rng = ChaCha12Rng::from_seed([0; 32]);

    // Generate random plaintext.
    let plaintext: Vec<u8> = core::iter::repeat_with(|| rng.gen::<u8>())
        .take(PLAINTEXT_SIZE)
        .collect();

    // Generate the Verifier's full encodings for each bit of the plaintext.
    let full_encodings = full_encodings(PLAINTEXT_SIZE * 8);

    // Prover's active encodings are based on their choice bits.
    let active_encodings = choose(&full_encodings, &plaintext.to_lsb0_vec());

    // Prover creates two commitments: to the front and to the tail portions of the plaintext.
    // Some middle bits of the plaintext will not be committed to.
    let range1 = 0..PLAINTEXT_SIZE / 2 - 10;
    let range2 = PLAINTEXT_SIZE / 2..PLAINTEXT_SIZE;
    let bitrange1 = range1.start * 8..range1.end * 8;
    let bitrange2 = range2.start * 8..range2.end * 8;

    let bit_ids1 = MockBitIds::new(Direction::Sent, &[range1.clone()]);
    let bit_ids2 = MockBitIds::new(Direction::Sent, &[range2.clone()]);

    let commitment1 = CommitmentData::new(
        &plaintext[range1.clone()],
        &active_encodings[bitrange1],
        bit_ids1,
    );
    let commitment2 = CommitmentData::new(
        &plaintext[range2.clone()],
        &active_encodings[bitrange2],
        bit_ids2,
    );

    vec![commitment1, commitment2]
}

pub fn encoding_provider() -> MockEncodingProvider<MockBitIds> {
    #[allow(clippy::single_range_in_vec_init)]
    let bit_ids = MockBitIds::new(Direction::Sent, &[0..PLAINTEXT_SIZE]);

    let full_encodings = full_encodings(PLAINTEXT_SIZE * 8)
        .iter()
        .map(|e| [Encoding::new(e[0], false), Encoding::new(e[1], true)])
        .collect::<Vec<_>>();

    MockEncodingProvider::new(FullEncodings::new(full_encodings, bit_ids))
}

/// Returns random full encodings for `len` bits.
fn full_encodings(len: usize) -> Vec<[[u8; 5]; 2]> {
    let mut rng = ChaCha12Rng::from_seed([1; 32]);

    let mut full_encodings = vec![[[0u8; SSP / 8]; 2]; len];
    for elem in full_encodings.iter_mut() {
        *elem = rng.gen();
    }
    full_encodings
}

/// Unzips a slice of pairs, returning items corresponding to choice.
pub fn choose<T: Clone>(items: &[[T; 2]], choice: &[bool]) -> Vec<T> {
    assert!(items.len() == choice.len(), "arrays have different lengths");
    items
        .iter()
        .zip(choice)
        .map(|(items, choice)| items[*choice as usize].clone())
        .collect()
}
