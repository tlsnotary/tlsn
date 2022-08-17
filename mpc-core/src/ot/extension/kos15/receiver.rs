use aes::{Aes128, BlockCipher, BlockEncrypt, NewBlockCipher};
use cipher::consts::U16;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;
use std::convert::TryInto;

use super::BaseSender;
use crate::{
    msgs::ot as msgs,
    ot::extension::{ExtReceiverCoreError, BASE_COUNT},
    utils::{self, sha256, u8vec_to_boolvec, xor},
    Block,
};
use clmul::Clmul;

#[derive(Clone, Debug, PartialEq)]
pub struct ChoiceState {
    choice: Vec<bool>,
    derandomized: Vec<bool>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum State {
    Initialized,
    BaseSetup,
    BaseSend,
    Setup(ChoiceState),
    Complete,
}

// Helper function for making sure the OT state machine is being used correctly
fn check_state(expected: &State, received: &State) -> Result<(), ExtReceiverCoreError> {
    if expected != received {
        Err(ExtReceiverCoreError::BadState(
            format!("{:?}", expected),
            format!("{:?}", received),
        ))
    } else {
        Ok(())
    }
}

pub struct Kos15Receiver<R = ChaCha12Rng, C = Aes128> {
    rng: R,
    cipher: C,
    base: BaseSender,
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

impl Kos15Receiver {
    pub fn new(count: usize) -> Self {
        let mut rng = ChaCha12Rng::from_entropy();
        let cointoss_share = rng.gen();
        Self {
            rng,
            cipher: Aes128::new_from_slice(&[0u8; 16]).unwrap(),
            base: BaseSender::default(),
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
    ciphertexts: &[[Block; 2]],
    table: &[Vec<u8>],
    choice: &[bool],
) -> Vec<Block> {
    let mut values: Vec<Block> = Vec::with_capacity(choice.len());
    for (j, b) in choice.iter().enumerate() {
        let t: [u8; 16] = table[j].clone().try_into().unwrap();
        let t = Block::from(t);
        let y = if *b {
            ciphertexts[j][1]
        } else {
            ciphertexts[j][0]
        };
        let y = y ^ t.hash_tweak(cipher, j);
        values.push(y);
    }
    values
}

impl<R, C> Kos15Receiver<R, C>
where
    R: Rng + CryptoRng,
    C: BlockCipher<BlockSize = U16> + BlockEncrypt,
{
    pub fn new_with_custom(mut rng: R, cipher: C, base: BaseSender, count: usize) -> Self {
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

// Implement standard OT methods
impl<R, C> Kos15Receiver<R, C>
where
    R: Rng + CryptoRng + SeedableRng,
    C: BlockCipher<BlockSize = U16> + BlockEncrypt,
{
    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn is_complete(&self) -> bool {
        self.state == State::Complete
    }

    pub fn base_setup(&mut self) -> Result<msgs::BaseSenderSetupWrapper, ExtReceiverCoreError> {
        check_state(&self.state, &State::Initialized)?;

        self.state = State::BaseSetup;
        Ok(msgs::BaseSenderSetupWrapper {
            setup: self.base.setup(&mut self.rng)?,
            cointoss_commit: sha256(&self.cointoss_share),
        })
    }

    pub fn base_send(
        &mut self,
        base_receiver_setup: msgs::BaseReceiverSetupWrapper,
    ) -> Result<msgs::BaseSenderPayloadWrapper, ExtReceiverCoreError> {
        check_state(&self.state, &State::BaseSetup)?;

        let mut seeds: Vec<[Block; 2]> = Vec::with_capacity(BASE_COUNT);
        for _ in 0..BASE_COUNT {
            seeds.push([Block::random(&mut self.rng), Block::random(&mut self.rng)]);
        }

        let base_send = self.base.send(&seeds, base_receiver_setup.setup)?;

        self.set_seeds(seeds);
        let mut result = [0u8; 32];
        xor(
            &base_receiver_setup.cointoss_share,
            &self.cointoss_share,
            &mut result,
        );
        self.cointoss_random = Some(result);
        self.state = State::BaseSend;
        Ok(msgs::BaseSenderPayloadWrapper {
            payload: base_send,
            cointoss_share: self.cointoss_share,
        })
    }

    pub fn extension_setup(
        &mut self,
        choice: &[bool],
    ) -> Result<msgs::ExtReceiverSetup, ExtReceiverCoreError> {
        check_state(&self.state, &State::BaseSend)?;

        // This is guaranteed to be set because we can only reach the BaseReceive by running
        // base_send(), which runs set_seeds(), which sets the RNGs
        let rngs = self
            .rngs
            .as_mut()
            .expect("RNGs were not set even when in State::BaseSend");

        // We will pad with extra bits to make the total count a multiple of 8
        // to make handling easier. Those extra paddings bits will be random and
        // will not be used for OT.
        let pad_count = if choice.len() % 8 == 0 {
            0
        } else {
            8 - choice.len() % 8
        };
        // Also add 256 extra bits which will be sacrificed as part of the
        // KOS15 protocol.
        // 1 extra byte is also added to contain "extra paddings bits" mentioned
        // above.
        let mut extra_bytes = [0u8; 33];
        self.rng.fill(&mut extra_bytes[..]);
        // extend choice bits with the exact amount of extra bits that we need.
        // Some bits of the 1 extra byte will be discarded.
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
        let mut rng = ChaCha12Rng::from_seed(
            self.cointoss_random
                .ok_or(ExtReceiverCoreError::InternalError)?,
        );

        let mut x = Clmul::new(&[0u8; 16]);
        let mut t0 = Clmul::new(&[0u8; 16]);
        let mut t1 = Clmul::new(&[0u8; 16]);
        for (j, xj) in r_bool.into_iter().enumerate() {
            let mut tj: [u8; 16] = [0u8; 16];
            tj.copy_from_slice(&ts[j]);
            let mut tj = Clmul::new(&tj);
            // chi is the random weight
            let chi: [u8; 16] = rng.gen();
            let mut chi = Clmul::new(&chi);
            if xj {
                x ^= chi;
            }
            // multiplication in the finite field (p.14 Implementation Optimizations.
            // suggests that it can be done without reduction).
            tj.clmul_reuse(&mut chi);
            t0 ^= tj;
            t1 ^= chi;
        }

        self.state = State::Setup(ChoiceState {
            choice: Vec::from(choice),
            derandomized: Vec::new(),
        });
        // remove the last 256 elements which were sacrificed
        ts.drain(ts.len() - 256..);
        self.table = Some(ts);
        Ok(msgs::ExtReceiverSetup {
            ncols,
            table: gs,
            x: x.into(),
            t0: t0.into(),
            t1: t1.into(),
        })
    }

    pub fn receive(
        &mut self,
        payload: msgs::ExtSenderPayload,
    ) -> Result<Vec<Block>, ExtReceiverCoreError> {
        let choice_state = match &mut self.state {
            State::Setup(state) => state,
            received => {
                return Err(ExtReceiverCoreError::BadState(
                    format!("Setup"),
                    format!("{:?}", received),
                ))
            }
        };

        if payload.ciphertexts.len() > choice_state.choice.len() {
            return Err(ExtReceiverCoreError::InvalidPayloadSize);
        }

        let choice: Vec<bool> = choice_state
            .choice
            .drain(..payload.ciphertexts.len())
            .collect();

        // This is guaranteed to be present because State::Setup is only set by extension_setup,
        // which sets self.table
        let table = self
            .table
            .as_mut()
            .expect("table was not set even when in State::Setup");
        let table: Vec<Vec<u8>> = table.drain(..choice.len()).collect();
        let values = decrypt_values(&mut self.cipher, &payload.ciphertexts, &table, &choice);

        if (choice_state.choice.len() == 0) && (choice_state.derandomized.len() == 0) {
            self.state = State::Complete;
        }

        Ok(values)
    }
}

// Implement random OT methods
impl<R, C> Kos15Receiver<R, C>
where
    R: Rng + CryptoRng + SeedableRng,
    C: BlockCipher<BlockSize = U16> + BlockEncrypt,
{
    pub fn rand_extension_setup(&mut self) -> Result<msgs::ExtReceiverSetup, ExtReceiverCoreError> {
        let n = self.count;
        // For random OT we generate random choice bits during setup then derandomize later
        let mut choice = vec![0u8; if n % 8 != 0 { n + (8 - n % 8) } else { n } / 8];
        self.rng.fill_bytes(&mut choice);
        let mut choice = u8vec_to_boolvec(&choice);
        choice.resize(n, false);

        self.extension_setup(&choice)
    }

    pub fn derandomize(
        &mut self,
        choice: &[bool],
    ) -> Result<msgs::ExtDerandomize, ExtReceiverCoreError> {
        let choice_state = match &mut self.state {
            State::Setup(state) => state,
            received => {
                return Err(ExtReceiverCoreError::BadState(
                    format!("Setup"),
                    format!("{:?}", received),
                ))
            }
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
        Ok(msgs::ExtDerandomize { flip })
    }

    pub fn rand_receive(
        &mut self,
        payload: msgs::ExtSenderPayload,
    ) -> Result<Vec<Block>, ExtReceiverCoreError> {
        let choice_state = match &mut self.state {
            State::Setup(state) => state,
            received => {
                return Err(ExtReceiverCoreError::BadState(
                    format!("Setup"),
                    format!("{:?}", received),
                ))
            }
        };

        if payload.ciphertexts.len() > choice_state.derandomized.len() {
            return Err(ExtReceiverCoreError::NotDerandomized);
        }

        let choice: Vec<bool> = choice_state
            .derandomized
            .drain(..payload.ciphertexts.len())
            .collect();

        // This is guaranteed to be present because State::Setup is only set by extension_setup,
        // which sets self.table
        let table = self
            .table
            .as_mut()
            .expect("table was not set even when in State::Setup");
        let table: Vec<Vec<u8>> = table.drain(..choice.len()).collect();
        let values = decrypt_values(&mut self.cipher, &payload.ciphertexts, &table, &choice);

        if (choice_state.choice.len() == 0) && (choice_state.derandomized.len() == 0) {
            self.state = State::Complete;
        }

        Ok(values)
    }
}
