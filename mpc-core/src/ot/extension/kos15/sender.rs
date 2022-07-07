use crate::block::Block;
use crate::ot::extension::{
    kos15::{
        BaseReceiver, BaseReceiverSetupWrapper, BaseSenderPayloadWrapper, BaseSenderSetupWrapper,
        ExtDerandomize, ExtReceiverSetup, ExtSenderPayload,
    },
    ExtRandomSendCore, ExtSenderCoreError, ExtStandardSendCore, BASE_COUNT,
};
use crate::utils::{self, sha256, xor};

use aes::{Aes128, BlockCipher, BlockEncrypt, NewBlockCipher};
use cipher::consts::U16;
use clmul::Clmul;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;
use std::convert::TryInto;

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub enum State {
    Initialized,
    BaseSetup,
    BaseReceive,
    Setup,
    Complete,
}

pub struct Kos15Sender<C = Aes128> {
    rng: ChaCha12Rng,
    cipher: C,
    base: BaseReceiver,
    state: State,
    count: usize,
    sent: usize,
    // choice bits for the base OT protocol
    base_choice: Vec<bool>,
    // seeds are the result of running base OT setup. They are used to seed the
    // RNGs.
    seeds: Option<Vec<Block>>,
    rngs: Option<Vec<ChaCha12Rng>>,
    // table's rows are such that for each row j:
    // table[j] = R[j], if Receiver's choice bit was 0 or
    // table[j] = R[j] ^ base_choice, if Receiver's choice bit was 1
    // (where R is the table which Receiver has. Note that base_choice is known
    // only to us).
    table: Option<Vec<Vec<u8>>>,
    // our XOR share for the cointoss protocol
    cointoss_share: [u8; 32],
    // the Receiver's sha256 commitment to their cointoss share
    receiver_cointoss_commit: Option<[u8; 32]>,
    // the shared random value which both parties will have at the end of the
    // cointoss protocol
    cointoss_random: Option<[u8; 32]>,
}

// Having 2 messages that Receiver chooses from, we encrypt each message with
// a unique mask (i.e. XOR the message them with the mask). Receiver who knows
// only 1 mask will be able to decrypt only 1 message out of 2.
fn encrypt_values<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &mut C,
    inputs: &[[Block; 2]],
    table: &[Vec<u8>],
    base_choice: &[bool],
    flip: Option<Vec<bool>>,
) -> Vec<[Block; 2]> {
    let mut ciphertexts: Vec<[Block; 2]> = Vec::with_capacity(table.len());
    let base_choice: [u8; 16] = utils::boolvec_to_u8vec(base_choice).try_into().unwrap();
    let delta = Block::from(base_choice);
    // If Receiver used *random* choice bits during OT extension setup, he will now
    // instruct us to de-randomize, so that the value corresponding to his *actual*
    // choice bit would be masked by that mask which Receiver knows.
    let flip = flip.unwrap_or(vec![false; inputs.len()]);
    for (j, (input, flip)) in inputs.iter().zip(flip).enumerate() {
        let q: [u8; 16] = table[j].clone().try_into().unwrap();
        let q = Block::from(q);
        let masks = [q.hash_tweak(cipher, j), (q ^ delta).hash_tweak(cipher, j)];
        if flip {
            ciphertexts.push([input[0] ^ masks[1], input[1] ^ masks[0]]);
        } else {
            ciphertexts.push([input[0] ^ masks[0], input[1] ^ masks[1]]);
        }
    }
    ciphertexts
}

impl Kos15Sender {
    pub fn new(count: usize) -> Self {
        let mut rng = ChaCha12Rng::from_entropy();

        let cointoss_share = rng.gen();
        let mut base_choice = vec![0u8; BASE_COUNT / 8];
        rng.fill_bytes(&mut base_choice);

        Self {
            rng,
            cipher: Aes128::new_from_slice(&[0u8; 16]).unwrap(),
            base: BaseReceiver::default(),
            state: State::Initialized,
            count,
            sent: 0,
            base_choice: utils::u8vec_to_boolvec(&base_choice),
            seeds: None,
            rngs: None,
            table: None,
            cointoss_share,
            receiver_cointoss_commit: None,
            cointoss_random: None,
        }
    }
}

impl<C> Kos15Sender<C>
where
    C: BlockCipher<BlockSize = U16> + BlockEncrypt,
{
    pub fn new_from_custom(cipher: C, base: BaseReceiver, count: usize) -> Self {
        let mut rng = ChaCha12Rng::from_entropy();

        let cointoss_share = rng.gen();
        let mut base_choice = vec![0u8; BASE_COUNT / 8];
        rng.fill_bytes(&mut base_choice);

        Self {
            rng,
            cipher,
            base,
            state: State::Initialized,
            count,
            sent: 0,
            base_choice: utils::u8vec_to_boolvec(&base_choice),
            seeds: None,
            rngs: None,
            table: None,
            cointoss_share,
            receiver_cointoss_commit: None,
            cointoss_random: None,
        }
    }

    fn set_seeds(&mut self, seeds: Vec<Block>) {
        let rngs: Vec<ChaCha12Rng> = seeds
            .iter()
            .map(|k| {
                let k: [u8; 16] = k.to_be_bytes();
                let k: [u8; 32] = [k, k]
                    .concat()
                    .try_into()
                    .expect("Could not convert block into [u8; 32]");
                ChaCha12Rng::from_seed(k)
            })
            .collect();
        self.seeds = Some(seeds);
        self.rngs = Some(rngs);
    }
}

impl<C> ExtStandardSendCore for Kos15Sender<C>
where
    C: BlockCipher<BlockSize = U16> + BlockEncrypt,
{
    type State = State;
    type BaseSenderSetup = BaseSenderSetupWrapper;
    type BaseSenderPayload = BaseSenderPayloadWrapper;
    type BaseReceiverSetup = BaseReceiverSetupWrapper;
    type ExtSenderPayload = ExtSenderPayload;
    type ExtReceiverSetup = ExtReceiverSetup;

    fn state(&self) -> &State {
        &self.state
    }

    fn is_complete(&self) -> bool {
        self.state == State::Complete
    }

    fn base_setup(
        &mut self,
        base_sender_setup: BaseSenderSetupWrapper,
    ) -> Result<BaseReceiverSetupWrapper, ExtSenderCoreError> {
        if self.state != State::Initialized {
            return Err(ExtSenderCoreError::WrongState);
        }
        self.receiver_cointoss_commit = Some(base_sender_setup.cointoss_commit);
        self.state = State::BaseSetup;
        Ok(BaseReceiverSetupWrapper {
            setup: self
                .base
                .setup(&mut self.rng, &self.base_choice, base_sender_setup.setup)?,
            cointoss_share: self.cointoss_share,
        })
    }

    fn base_receive(
        &mut self,
        payload: BaseSenderPayloadWrapper,
    ) -> Result<(), ExtSenderCoreError> {
        if self.state != State::BaseSetup {
            return Err(ExtSenderCoreError::WrongState);
        }
        let receive = self.base.receive(payload.payload)?;
        self.set_seeds(receive);

        // check the decommitment for the other party's share
        if sha256(&payload.cointoss_share)
            != self
                .receiver_cointoss_commit
                .ok_or(ExtSenderCoreError::InternalError)?
        {
            return Err(ExtSenderCoreError::CommitmentCheckFailed);
        }
        let mut result = [0u8; 32];
        xor(&payload.cointoss_share, &self.cointoss_share, &mut result);
        self.cointoss_random = Some(result);

        self.state = State::BaseReceive;
        Ok(())
    }

    fn extension_setup(
        &mut self,
        receiver_setup: ExtReceiverSetup,
    ) -> Result<(), ExtSenderCoreError> {
        if self.state != State::BaseReceive {
            return Err(ExtSenderCoreError::BaseOTNotSetup);
        }
        let ncols = receiver_setup.table[0].len() * 8;
        let us = receiver_setup.table;
        let mut qs: Vec<Vec<u8>> = vec![vec![0u8; ncols / 8]; BASE_COUNT];

        let rngs = self
            .rngs
            .as_mut()
            .ok_or(ExtSenderCoreError::BaseOTNotSetup)?;

        for j in 0..BASE_COUNT {
            rngs[j].fill_bytes(&mut qs[j]);
            if self.base_choice[j] {
                qs[j] = qs[j].iter().zip(&us[j]).map(|(q, u)| *q ^ *u).collect();
            }
        }
        let mut qs = utils::transpose(&qs);

        // Check correlation
        // The check is explaned in the KOS15 paper in a paragraph on page 8
        // starting with "To carry out the check..."
        // We use the exact same notation as the paper.

        // Seeding with a value from cointoss so that neither party could influence
        // the randomness
        let mut rng = ChaCha12Rng::from_seed(
            self.cointoss_random
                .ok_or(ExtSenderCoreError::InternalError)?,
        );

        let mut check0 = Clmul::new(&[0u8; 16]);
        let mut check1 = Clmul::new(&[0u8; 16]);
        for j in 0..ncols {
            let mut q: [u8; 16] = [0u8; 16];
            q.copy_from_slice(&qs[j]);
            let mut q = Clmul::new(&q);
            // chi is the random weight
            let chi: [u8; 16] = rng.gen();
            let mut chi = Clmul::new(&chi);

            // multiplication in the finite field (p.14 Implementation Optimizations.
            // suggests that it can be done without reduction).
            q.clmul_reuse(&mut chi);
            check0 ^= q;
            check1 ^= chi;
        }

        let mut delta: [u8; 16] = [0u8; 16];
        delta.copy_from_slice(&utils::boolvec_to_u8vec(&self.base_choice));
        let delta = Clmul::new(&delta);

        let mut x: [u8; 16] = [0u8; 16];
        x.copy_from_slice(&receiver_setup.x);
        let x = Clmul::new(&x);

        let mut t0: [u8; 16] = [0u8; 16];
        t0.copy_from_slice(&receiver_setup.t0);
        let t0 = Clmul::new(&t0);

        let mut t1: [u8; 16] = [0u8; 16];
        t1.copy_from_slice(&receiver_setup.t1);
        let t1 = Clmul::new(&t1);

        let (tmp0, tmp1) = x.clmul(delta);
        check0 ^= tmp0;
        check1 ^= tmp1;
        if !(check0 == t0 && check1 == t1) {
            return Err(ExtSenderCoreError::ConsistencyCheckFailed);
        }

        // remove the last 256 elements which were sacrificed during the
        // KOS check
        qs.drain(qs.len() - 256..);
        self.table = Some(qs);
        self.state = State::Initialized;
        Ok(())
    }

    fn send(&mut self, inputs: &[[Block; 2]]) -> Result<ExtSenderPayload, ExtSenderCoreError> {
        if self.sent + inputs.len() > self.count {
            return Err(ExtSenderCoreError::InvalidInputLength);
        }
        match self.state {
            State::Initialized => {}
            State::Complete => return Err(ExtSenderCoreError::AlreadyComplete),
            _ => return Err(ExtSenderCoreError::NotSetup),
        };

        let table = self.table.as_mut().ok_or(ExtSenderCoreError::NotSetup)?;
        let table: Vec<Vec<u8>> = table.drain(..inputs.len()).collect();
        let ciphertexts = encrypt_values(&mut self.cipher, inputs, &table, &self.base_choice, None);

        self.sent += inputs.len();
        if self.sent == self.count {
            self.state = State::Complete;
        }

        Ok(ExtSenderPayload { ciphertexts })
    }
}

impl<C> ExtRandomSendCore for Kos15Sender<C>
where
    C: BlockCipher<BlockSize = U16> + BlockEncrypt,
{
    type ExtDerandomize = ExtDerandomize;

    fn rand_send(
        &mut self,
        inputs: &[[Block; 2]],
        derandomize: ExtDerandomize,
    ) -> Result<ExtSenderPayload, ExtSenderCoreError> {
        if self.sent + inputs.len() > self.count {
            return Err(ExtSenderCoreError::InvalidInputLength);
        }
        match self.state {
            State::Initialized => {}
            State::Complete => return Err(ExtSenderCoreError::AlreadyComplete),
            _ => return Err(ExtSenderCoreError::NotSetup),
        };

        let table = self.table.as_mut().ok_or(ExtSenderCoreError::NotSetup)?;
        let table: Vec<Vec<u8>> = table.drain(..inputs.len()).collect();
        let ciphertexts = encrypt_values(
            &mut self.cipher,
            inputs,
            &table,
            &self.base_choice,
            Some(derandomize.flip),
        );

        self.sent += inputs.len();
        if self.sent == self.count {
            self.state = State::Complete;
        }

        Ok(ExtSenderPayload { ciphertexts })
    }
}
