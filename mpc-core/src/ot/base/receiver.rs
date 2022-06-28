use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar,
};
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

use super::{ReceiveCore, ReceiverCoreError, SenderPayload, SenderSetup};
use crate::Block;

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub enum State {
    Initialized,
    Setup,
    Complete,
}

pub struct ReceiverCore<R = ChaCha12Rng> {
    rng: R,
    count: usize,
    hashes: Option<Vec<Block>>,
    choice: Option<Vec<bool>>,
    state: State,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ReceiverSetup {
    pub keys: Vec<RistrettoPoint>,
}

impl ReceiverCore {
    pub fn new(count: usize) -> Self {
        Self {
            rng: ChaCha12Rng::from_entropy(),
            count,
            hashes: None,
            choice: None,
            state: State::Initialized,
        }
    }
}

impl<R: Rng + CryptoRng> ReceiverCore<R> {
    pub fn new_from_rng(rng: R, count: usize) -> Self {
        Self {
            rng,
            count,
            hashes: None,
            choice: None,
            state: State::Initialized,
        }
    }
}

impl<R: Rng + CryptoRng> ReceiveCore for ReceiverCore<R> {
    fn state(&self) -> State {
        self.state
    }

    fn setup(
        &mut self,
        choice: &[bool],
        sender_setup: SenderSetup,
    ) -> Result<ReceiverSetup, ReceiverCoreError> {
        if choice.len() != self.count {
            return Err(ReceiverCoreError::InvalidChoiceLength);
        }
        // point_table is A in [ref1]
        let point_table = RistrettoBasepointTable::create(&sender_setup.public_key);
        let zero = &Scalar::zero() * &point_table;
        let one = &Scalar::one() * &point_table;
        let (keys, hashes): (Vec<RistrettoPoint>, Vec<Block>) = choice
            .iter()
            .enumerate()
            .map(|(i, b)| {
                // x is b in [ref1]
                let x = Scalar::random(&mut self.rng);
                let c = if *b { one } else { zero };
                // k is B in [ref1]
                let k = c + &x * &RISTRETTO_BASEPOINT_TABLE;
                // h is k_r in [ref1] == hash(A^b)
                let h = Block::hash_point(&(&x * &point_table), i as u32);
                // we send the k values to the Sender and keep the h values
                (k, h)
            })
            .unzip();
        self.hashes = Some(hashes);
        self.choice = Some(Vec::from(choice));
        self.state = State::Setup;

        Ok(ReceiverSetup { keys })
    }

    fn receive(&mut self, payload: SenderPayload) -> Result<Vec<Block>, ReceiverCoreError> {
        if self.state < State::Setup {
            return Err(ReceiverCoreError::NotSetup);
        }

        let hashes = self.hashes.as_ref().unwrap();
        let values: Vec<Block> = self
            .choice
            .as_ref()
            .unwrap()
            .iter()
            .zip(hashes)
            .zip(payload.encrypted_values.iter())
            .map(|((c, h), v)| {
                // select an encrypted value based on the choice bit
                let b = if *c { v[1] } else { v[0] };
                // decrypt it with the corresponding key (the key is a hash)
                *h ^ b
            })
            .collect();

        self.state = State::Complete;

        Ok(values)
    }
}
