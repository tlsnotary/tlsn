use aes::{Aes128, BlockCipher, BlockEncrypt, NewBlockCipher};
use cipher::consts::U16;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;
use std::convert::TryInto;

use super::u64x2::U64x2;
use super::{
    BaseReceiverSetup, ExtRandomReceiveCore, ExtReceiveCore, ExtReceiverCoreError,
    ExtSenderPayload, BASE_COUNT,
};
use crate::block::Block;
use crate::ot::base::{SenderPayload, SenderSetup};
use crate::ot::{SendCore, SenderCore};
use crate::utils::{self, sha256, u8vec_to_boolvec, xor};

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

// OT extension Receiver plays the role of base OT Sender and sends the
// first message containing base OT setup and cointoss commitment
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BaseSenderSetup {
    pub setup: SenderSetup,
    // Cointoss protocol's 1st message: sha256 commitment
    pub cointoss_commit: [u8; 32],
}

#[derive(Debug, Clone, PartialEq)]
pub struct BaseSenderPayload {
    pub payload: SenderPayload,
    // Cointoss protocol's 3rd message: Sender reveals share
    pub cointoss_share: [u8; 32],
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
    // our XOR share for the cointoss protocol
    cointoss_share: [u8; 32],
    // the shared random value which both parties will have at the end of the
    // cointoss protocol
    cointoss_random: Option<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct ExtReceiverSetup {
    pub ncols: usize,
    pub table: Vec<Vec<u8>>,
    // x, t0, t1 are used for the KOS15 check
    pub x: [u8; 16],
    pub t0: [u8; 16],
    pub t1: [u8; 16],
}

#[derive(Clone, Debug)]
pub struct ExtDerandomize {
    pub flip: Vec<bool>,
}

impl ExtReceiverCore {
    pub fn new(count: usize) -> Self {
        let mut rng = ChaCha12Rng::from_entropy();
        let cointoss_share = rng.gen();
        Self {
            rng,
            cipher: Aes128::new_from_slice(&[0u8; 16]).unwrap(),
            base: SenderCore::new(BASE_COUNT),
            state: State::Initialized,
            count,
            seeds: None,
            rngs: None,
            table: None,
            cointoss_share,
            cointoss_random: None,
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
    pub fn new_with_custom(mut rng: R, cipher: C, base: OT, count: usize) -> Self {
        let cointoss_share = rng.gen();
        Self {
            rng,
            cipher,
            base,
            state: State::Initialized,
            count,
            seeds: None,
            rngs: None,
            table: None,
            cointoss_share,
            cointoss_random: None,
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
        Ok(BaseSenderSetup {
            setup: self.base.setup(),
            cointoss_commit: sha256(&self.cointoss_share),
        })
    }

    fn base_send(
        &mut self,
        base_receiver_setup: BaseReceiverSetup,
    ) -> Result<BaseSenderPayload, ExtReceiverCoreError> {
        let mut seeds: Vec<[Block; 2]> = Vec::with_capacity(BASE_COUNT);
        for _ in 0..BASE_COUNT {
            seeds.push([Block::random(&mut self.rng), Block::random(&mut self.rng)]);
        }

        let base_send = self
            .base
            .send(seeds.as_slice(), base_receiver_setup.setup)?;

        self.set_seeds(seeds);
        let mut result = [0u8; 32];
        result.copy_from_slice(&xor(
            &base_receiver_setup.cointoss_share,
            &self.cointoss_share,
        ));
        self.cointoss_random = Some(result);
        self.state = State::BaseSetup;
        Ok(BaseSenderPayload {
            payload: base_send,
            cointoss_share: self.cointoss_share,
        })
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

        // We will pad with extra bits to make the total count a multiple of 8
        // to make handling easier
        let pad_count = if choice.len() % 8 == 0 {
            0
        } else {
            8 - choice.len() % 8
        };
        // Also add 256 extra bits which will be sacrificed as part of the
        // KOS15 protocol
        let mut extra_bytes = [0u8; 33];
        self.rng.fill(&mut extra_bytes[..]);
        // extend choice bits with the exact amount of extra bits that we need
        let mut r_bool = choice.to_vec();
        r_bool.extend(utils::u8vec_to_boolvec(&extra_bytes)[0..pad_count + 256].iter());
        let r = utils::boolvec_to_u8vec(&r_bool);

        let ncols = r_bool.len();
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
        let mut ts = utils::transpose(&ts);

        // Check correlation
        // The check is explaned in the KOS15 paper in a paragraph on page 8
        // starting with "To carry out the check..."
        // We use the exact same notation as the paper.

        // Seeding with a value from cointoss so that neither party could influence
        // the randomness
        let mut rng = ChaCha12Rng::from_seed(self.cointoss_random.unwrap());

        let mut x = U64x2::from([0u8; 16]);
        let mut t0 = U64x2::from([0u8; 16]);
        let mut t1 = U64x2::from([0u8; 16]);
        for (j, xj) in r_bool.into_iter().enumerate() {
            let tj = U64x2::from(&ts[j]);
            // chi is the random weight
            let chi = U64x2::random(&mut rng);
            if xj {
                x = x ^ chi;
            }
            // multiplication in the finite field (p.14 Implementation Optimizations.
            // suggests that it can be done without reduction).
            let (tmp0, tmp1) = tj * chi;
            t0 = t0 ^ tmp0;
            t1 = t1 ^ tmp1;
        }

        self.state = State::Setup(ChoiceState {
            choice: Vec::from(choice),
            derandomized: Vec::new(),
        });
        // remove the last 256 elements which were sacrificed
        ts.drain(ts.len() - 256..);
        self.table = Some(ts);
        Ok(ExtReceiverSetup {
            ncols,
            table: gs,
            x: x.to_array(),
            t0: t0.to_array(),
            t1: t1.to_array(),
        })
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
