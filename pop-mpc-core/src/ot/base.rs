use super::errors::BaseOtReceiverError;
use crate::Block;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{CompressedRistretto, RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar,
};
use rand::{CryptoRng, Rng};
use std::convert::TryInto;

use super::BaseOtSenderError;

////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////// BaseOtSender

#[derive(Clone, Copy, Debug, PartialEq)]
enum SenderState {
    Initialized,
    Setup,
    Complete,
}

pub struct BaseOtSender {
    private_key: Scalar,
    public_key: RistrettoPoint,
    state: SenderState,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BaseOtSenderSetup {
    pub public_key: RistrettoPoint,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BaseOtSenderPayload {
    pub encrypted_values: Vec<[Block; 2]>,
}

impl BaseOtSender {
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let private_key = Scalar::random(rng);
        Self {
            private_key,
            public_key: &private_key * &RISTRETTO_BASEPOINT_TABLE,
            state: SenderState::Initialized,
        }
    }

    pub fn setup(&mut self) -> BaseOtSenderSetup {
        self.state = SenderState::Setup;
        BaseOtSenderSetup {
            public_key: self.public_key,
        }
    }

    pub fn send(
        &mut self,
        inputs: &[[Block; 2]],
        receiver_setup: BaseOtReceiverSetup,
    ) -> Result<BaseOtSenderPayload, BaseOtSenderError> {
        let ninputs = inputs.len();
        let ys = self.private_key * self.public_key;
        let mut encrypted_values: Vec<[Block; 2]> = Vec::with_capacity(ninputs);

        for (i, (input, receiver_key)) in inputs.iter().zip(receiver_setup.keys).enumerate() {
            let yr = self.private_key * receiver_key;
            let k0 = Block::hash_point(&yr, i);
            let k1 = Block::hash_point(&(yr - ys), i);
            encrypted_values.push([k0 ^ input[0], k1 ^ input[1]]);
        }

        self.state = SenderState::Complete;

        Ok(BaseOtSenderPayload { encrypted_values })
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////// BaseOtReceiver

#[derive(Clone, Copy, Debug, PartialEq)]
enum ReceiverState {
    Initialized,
    Setup,
    Complete,
}

pub struct BaseOtReceiver {
    hashes: Option<Vec<Block>>,
    state: ReceiverState,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BaseOtReceiverSetup {
    pub keys: Vec<RistrettoPoint>,
}

impl BaseOtReceiver {
    pub fn new() -> Self {
        Self {
            hashes: None,
            state: ReceiverState::Initialized,
        }
    }

    pub fn setup<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
        choice: &[bool],
        sender_setup: BaseOtSenderSetup,
    ) -> Result<BaseOtReceiverSetup, BaseOtReceiverError> {
        let point_table = RistrettoBasepointTable::create(&sender_setup.public_key);
        let zero = &Scalar::zero() * &point_table;
        let one = &Scalar::one() * &point_table;
        let (keys, hashes): (Vec<RistrettoPoint>, Vec<Block>) = choice
            .iter()
            .enumerate()
            .map(|(i, b)| {
                let x = Scalar::random(rng);
                let c = if *b { one } else { zero };
                let k = c + &x * &RISTRETTO_BASEPOINT_TABLE;
                let h = Block::hash_point(&(&x * &point_table), i);
                (k, h)
            })
            .unzip();
        self.hashes = Some(hashes);

        self.state = ReceiverState::Setup;

        Ok(BaseOtReceiverSetup { keys })
    }

    pub fn receive(&mut self, choice: &[bool], payload: BaseOtSenderPayload) -> Vec<Block> {
        let hashes = self.hashes.as_ref().unwrap();
        let values: Vec<Block> = choice
            .iter()
            .zip(hashes)
            .zip(payload.encrypted_values.iter())
            .map(|((c, h), v)| {
                let b = if *c { v[1] } else { v[0] };
                *h ^ b
            })
            .collect();

        self.state = ReceiverState::Complete;

        values
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::u8vec_to_boolvec;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    #[test]
    fn test_base_ot() {
        let mut s_rng = ChaCha12Rng::from_entropy();
        let mut r_rng = ChaCha12Rng::from_entropy();

        let mut rng = ChaCha12Rng::from_entropy();
        let s_inputs: Vec<[Block; 2]> = (0..128)
            .map(|i| [Block::random(&mut rng), Block::random(&mut rng)])
            .collect();
        let mut choice = vec![0u8; 16];
        rng.fill_bytes(&mut choice);
        let choice = u8vec_to_boolvec(&choice);
        let expected: Vec<Block> = s_inputs
            .iter()
            .zip(choice.iter())
            .map(|(input, choice)| input[*choice as usize])
            .collect();

        let mut sender = BaseOtSender::new(&mut s_rng);
        let sender_setup = sender.setup();

        let mut receiver = BaseOtReceiver::new();
        let receiver_setup = receiver.setup(&mut r_rng, &choice, sender_setup).unwrap();

        let send = sender.send(&s_inputs, receiver_setup).unwrap();
        let receive = receiver.receive(&choice, send);
        assert_eq!(expected, receive);
    }
}
