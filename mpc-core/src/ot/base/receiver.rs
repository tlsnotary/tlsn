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

pub struct ReceiverCore<R> {
    rng: R,
    hashes: Option<Vec<Block>>,
    choice: Option<Vec<bool>>,
    state: State,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ReceiverSetup {
    pub keys: Vec<RistrettoPoint>,
}

impl Default for ReceiverCore<ChaCha12Rng> {
    fn default() -> Self {
        Self::new(ChaCha12Rng::from_entropy())
    }
}

impl<R: Rng + CryptoRng> ReceiverCore<R> {
    pub fn new(rng: R) -> Self {
        Self {
            rng,
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
        let point_table = RistrettoBasepointTable::create(&sender_setup.public_key);
        let zero = &Scalar::zero() * &point_table;
        let one = &Scalar::one() * &point_table;
        let (keys, hashes): (Vec<RistrettoPoint>, Vec<Block>) = choice
            .iter()
            .enumerate()
            .map(|(i, b)| {
                let x = Scalar::random(&mut self.rng);
                let c = if *b { one } else { zero };
                let k = c + &x * &RISTRETTO_BASEPOINT_TABLE;
                let h = Block::hash_point(&(&x * &point_table), i);
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
                let b = if *c { v[1] } else { v[0] };
                *h ^ b
            })
            .collect();

        self.state = State::Complete;

        Ok(values)
    }
}
