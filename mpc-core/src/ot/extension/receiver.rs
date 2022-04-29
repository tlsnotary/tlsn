use aes::{Aes128, BlockCipher, BlockEncrypt, NewBlockCipher};
use cipher::consts::U16;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;
use std::convert::TryInto;

use super::{
    ExtRandomReceiveCore, ExtReceiveCore, ExtReceiverCoreError, ExtSenderPayload, BASE_COUNT,
};
use crate::block::Block;
use crate::ot::base::{
    ReceiverSetup as BaseReceiverSetup, SenderPayload as BaseSenderPayload,
    SenderSetup as BaseSenderSetup,
};
use crate::ot::{SendCore, SenderCore};
use crate::utils::{self, u8vec_to_boolvec};

#[derive(Clone, Debug, PartialEq)]
pub struct ChoiceState {
    choice: Vec<bool>,
    derandomized: Vec<bool>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum State {
    Initialized,
    BaseSetup,
    Setup(ChoiceState),
    Complete,
}

pub struct ExtReceiverCore<R = ChaCha12Rng, C = Aes128, OT = SenderCore<ChaCha12Rng>> {
    rng: R,
    cipher: C,
    base: OT,
    state: State,
    count: usize,
    // seeds are the result of running base OT setup. They are used to seed the
    // RNGs.
    seeds: Option<Vec<[Block; 2]>>,
    rngs: Option<Vec<[ChaCha12Rng; 2]>>,
    table: Option<Vec<Vec<u8>>>,
}

#[derive(Clone, Debug)]
pub struct ExtReceiverSetup {
    pub ncols: usize,
    pub table: Vec<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct ExtDerandomize {
    pub flip: Vec<bool>,
}

impl ExtReceiverCore {
    pub fn new(count: usize) -> Self {
        Self {
            rng: ChaCha12Rng::from_entropy(),
            cipher: Aes128::new_from_slice(&[0u8; 16]).unwrap(),
            base: SenderCore::new(BASE_COUNT),
            state: State::Initialized,
            count,
            seeds: None,
            rngs: None,
            table: None,
        }
    }
}

fn decrypt_values<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &mut C,
    encrypted_values: &[[Block; 2]],
    table: &[Vec<u8>],
    choice: &[bool],
) -> Vec<Block> {
    let mut values: Vec<Block> = Vec::with_capacity(choice.len());
    for (j, b) in choice.iter().enumerate() {
        let t: [u8; 16] = table[j].clone().try_into().unwrap();
        let t = Block::from(t);
        let y = if *b {
            encrypted_values[j][1]
        } else {
            encrypted_values[j][0]
        };
        let y = y ^ t.hash_tweak(cipher, j);
        values.push(y);
    }
    values
}

impl<R, C, OT> ExtReceiverCore<R, C, OT>
where
    R: Rng + CryptoRng,
    C: BlockCipher<BlockSize = U16> + BlockEncrypt,
    OT: SendCore,
{
    pub fn new_with_custom(rng: R, cipher: C, base: OT, count: usize) -> Self {
        Self {
            rng,
            cipher,
            base,
            state: State::Initialized,
            count,
            seeds: None,
            rngs: None,
            table: None,
        }
    }

    fn set_seeds(&mut self, seeds: Vec<[Block; 2]>) {
        let rngs: Vec<[ChaCha12Rng; 2]> = seeds
            .iter()
            .map(|k| {
                let k0: [u8; 16] = k[0].to_be_bytes();
                let k1: [u8; 16] = k[1].to_be_bytes();
                let k0: [u8; 32] = [k0, k0]
                    .concat()
                    .try_into()
                    .expect("Could not convert block into [u8; 32]");
                let k1: [u8; 32] = [k1, k1]
                    .concat()
                    .try_into()
                    .expect("Could not convert block into [u8; 32]");
                [ChaCha12Rng::from_seed(k0), ChaCha12Rng::from_seed(k1)]
            })
            .collect();
        self.seeds = Some(seeds);
        self.rngs = Some(rngs);
    }
}

impl<R, C, OT> ExtReceiveCore for ExtReceiverCore<R, C, OT>
where
    R: Rng + CryptoRng + SeedableRng,
    C: BlockCipher<BlockSize = U16> + BlockEncrypt,
    OT: SendCore,
{
    fn state(&self) -> &State {
        &self.state
    }

    fn is_complete(&self) -> bool {
        self.state == State::Complete
    }

    fn base_setup(&mut self) -> Result<BaseSenderSetup, ExtReceiverCoreError> {
        Ok(self.base.setup())
    }

    fn base_send(
        &mut self,
        base_receiver_setup: BaseReceiverSetup,
    ) -> Result<BaseSenderPayload, ExtReceiverCoreError> {
        let mut seeds: Vec<[Block; 2]> = Vec::with_capacity(BASE_COUNT);
        for _ in 0..BASE_COUNT {
            seeds.push([Block::random(&mut self.rng), Block::random(&mut self.rng)]);
        }

        let base_send = self.base.send(seeds.as_slice(), base_receiver_setup)?;

        self.set_seeds(seeds);
        self.state = State::BaseSetup;
        Ok(base_send)
    }

    fn extension_setup(
        &mut self,
        choice: &[bool],
    ) -> Result<ExtReceiverSetup, ExtReceiverCoreError> {
        if State::BaseSetup != self.state {
            return Err(ExtReceiverCoreError::BaseOTNotSetup);
        }
        let rngs = self
            .rngs
            .as_mut()
            .ok_or(ExtReceiverCoreError::BaseOTNotSetup)?;

        // The amount of choice bits must be equal to the amount of OT instances
        // needed plus extra 256 instances which will be sacrificed as part of the
        // KOS protocol.
        let r = utils::boolvec_to_u8vec(choice);
        let m = choice.len();
        let ncols = if m % 8 != 0 { m + (8 - m % 8) } else { m };
        let mut ts: Vec<Vec<u8>> = vec![vec![0u8; ncols / 8]; BASE_COUNT];
        let mut gs: Vec<Vec<u8>> = vec![vec![0u8; ncols / 8]; BASE_COUNT];

        // Note that for each row j of the matrix gs which will be sent to Sender,
        // Sender knows either rng[0] or rng[1] depending on his choice bit during
        // base OT. If he knows rng[1] then he will XOR it with gs[j] and get a
        // row ( ts[j] ^ r ). But if he knows rng[0] then his row will be ts[j].
        for j in 0..BASE_COUNT {
            rngs[j][0].fill_bytes(&mut ts[j]);
            rngs[j][1].fill_bytes(&mut gs[j]);
            gs[j] = gs[j]
                .iter()
                .zip(&ts[j])
                .zip(&r)
                .map(|((g, t), r)| *g ^ *t ^ *r)
                .collect();
        }

        // After Sender transposes his matrix, he will have a table S such that
        // for each row j:
        // self.table[j] = S[j], if our choice bit was 0 or
        // self.table[j] = S[j] ^ delta, if our choice bit was 1
        // (note that delta is known only to Sender)
        self.table = Some(utils::transpose(&ts));
        self.state = State::Setup(ChoiceState {
            choice: Vec::from(choice),
            derandomized: Vec::new(),
        });

        Ok(ExtReceiverSetup { ncols, table: gs })
    }

    fn receive(&mut self, payload: ExtSenderPayload) -> Result<Vec<Block>, ExtReceiverCoreError> {
        let choice_state = match &mut self.state {
            State::Setup(state) => state,
            State::Complete => return Err(ExtReceiverCoreError::AlreadyComplete),
            _ => return Err(ExtReceiverCoreError::NotSetup),
        };

        if payload.encrypted_values.len() > choice_state.choice.len() {
            return Err(ExtReceiverCoreError::InvalidPayloadSize);
        }

        let choice: Vec<bool> = choice_state
            .choice
            .drain(..payload.encrypted_values.len())
            .collect();

        let table = self.table.as_mut().ok_or(ExtReceiverCoreError::NotSetup)?;
        let table: Vec<Vec<u8>> = table.drain(..choice.len()).collect();
        let values = decrypt_values(&mut self.cipher, &payload.encrypted_values, &table, &choice);

        if (choice_state.choice.len() == 0) && (choice_state.derandomized.len() == 0) {
            self.state = State::Complete;
        }

        Ok(values)
    }
}

impl<R, C, OT> ExtRandomReceiveCore for ExtReceiverCore<R, C, OT>
where
    R: Rng + CryptoRng + SeedableRng,
    C: BlockCipher<BlockSize = U16> + BlockEncrypt,
    OT: SendCore,
{
    fn extension_setup(&mut self) -> Result<ExtReceiverSetup, ExtReceiverCoreError> {
        let n = self.count;
        // For random OT we generate random choice bits during setup then derandomize later
        let mut choice = vec![0u8; if n % 8 != 0 { n + (8 - n % 8) } else { n } / 8];
        self.rng.fill_bytes(&mut choice);
        let mut choice = u8vec_to_boolvec(&choice);
        choice.resize(n, false);

        ExtReceiveCore::extension_setup(self, &choice)
    }

    fn derandomize(&mut self, choice: &[bool]) -> Result<ExtDerandomize, ExtReceiverCoreError> {
        let choice_state = match &mut self.state {
            State::Setup(state) => state,
            State::Complete => return Err(ExtReceiverCoreError::AlreadyComplete),
            _ => return Err(ExtReceiverCoreError::NotSetup),
        };

        if choice.len() > choice_state.choice.len() {
            return Err(ExtReceiverCoreError::InvalidChoiceLength);
        }

        let random_choice: Vec<bool> = choice_state.choice.drain(..choice.len()).collect();
        let flip: Vec<bool> = random_choice
            .iter()
            .zip(choice)
            .map(|(a, b)| a ^ b)
            .collect();

        choice_state.derandomized.extend_from_slice(choice);
        Ok(ExtDerandomize { flip })
    }

    fn receive(&mut self, payload: ExtSenderPayload) -> Result<Vec<Block>, ExtReceiverCoreError> {
        let choice_state = match &mut self.state {
            State::Setup(state) => state,
            State::Complete => return Err(ExtReceiverCoreError::AlreadyComplete),
            _ => return Err(ExtReceiverCoreError::NotSetup),
        };

        if payload.encrypted_values.len() > choice_state.derandomized.len() {
            return Err(ExtReceiverCoreError::NotDerandomized);
        }

        let choice: Vec<bool> = choice_state
            .derandomized
            .drain(..payload.encrypted_values.len())
            .collect();
        let table = self.table.as_mut().ok_or(ExtReceiverCoreError::NotSetup)?;
        let table: Vec<Vec<u8>> = table.drain(..choice.len()).collect();
        let values = decrypt_values(&mut self.cipher, &payload.encrypted_values, &table, &choice);

        if (choice_state.choice.len() == 0) && (choice_state.derandomized.len() == 0) {
            self.state = State::Complete;
        }

        Ok(values)
    }
}
