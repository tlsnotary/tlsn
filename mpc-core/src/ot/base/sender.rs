use crate::Block;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE, ristretto::RistrettoPoint, scalar::Scalar,
};
use rand::{CryptoRng, Rng};
use rand_chacha::ChaCha12Rng;
use rand_core::SeedableRng;

use super::{ReceiverSetup, SendCore, SenderCoreError};

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub enum State {
    Initialized,
    Setup,
    Complete,
}

pub struct SenderCore<R> {
    rng: R,
    private_key: Option<Scalar>,
    public_key: Option<RistrettoPoint>,
    state: State,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SenderSetup {
    pub public_key: RistrettoPoint,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SenderPayload {
    pub encrypted_values: Vec<[Block; 2]>,
}

impl Default for SenderCore<ChaCha12Rng> {
    fn default() -> Self {
        Self::new(ChaCha12Rng::from_entropy())
    }
}

impl<R: Rng + CryptoRng> SenderCore<R> {
    pub fn new(rng: R) -> Self {
        Self {
            rng,
            private_key: None,
            public_key: None,
            state: State::Initialized,
        }
    }
}

impl<R: Rng + CryptoRng> SendCore for SenderCore<R> {
    fn state(&self) -> State {
        self.state
    }

    fn setup(&mut self) -> SenderSetup {
        let private_key = Scalar::random(&mut self.rng);
        self.public_key = Some(&private_key * &RISTRETTO_BASEPOINT_TABLE);
        self.private_key = Some(private_key);
        self.state = State::Setup;
        SenderSetup {
            public_key: self.public_key.unwrap(),
        }
    }

    fn send(
        &mut self,
        inputs: &[[Block; 2]],
        receiver_setup: ReceiverSetup,
    ) -> Result<SenderPayload, SenderCoreError> {
        if self.state < State::Setup {
            return Err(SenderCoreError::NotSetup);
        }
        let private_key = self.private_key.unwrap();
        let ninputs = inputs.len();
        let ys = private_key * self.public_key.unwrap();
        let mut encrypted_values: Vec<[Block; 2]> = Vec::with_capacity(ninputs);

        for (i, (input, receiver_key)) in inputs.iter().zip(receiver_setup.keys).enumerate() {
            let yr = private_key * receiver_key;
            let k0 = Block::hash_point(&yr, i);
            let k1 = Block::hash_point(&(yr - ys), i);
            encrypted_values.push([k0 ^ input[0], k1 ^ input[1]]);
        }

        self.state = State::Complete;

        Ok(SenderPayload { encrypted_values })
    }
}
