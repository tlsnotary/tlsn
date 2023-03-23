pub mod error;
pub mod state;

use super::{
    matrix::{Error as MatrixError, KosMatrix},
    utils::{calc_padding, decrypt_values, kos15_check_receiver, seed_rngs_from_nested},
    BASE_COUNT,
};
use crate::{
    msgs::{
        BaseReceiverSetupWrapper, BaseSenderPayloadWrapper, BaseSenderSetupWrapper, ExtDerandomize,
        ExtReceiverSetup, ExtSenderPayload, ExtSenderReveal,
    },
    DhOtSender as BaseSender, Kos15Sender,
};
use aes::{Aes128, NewBlockCipher};
use error::{CommittedOTError, ExtReceiverCoreError};
use mpc_core::{utils::blake3, Block};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;
use rand_core::RngCore;
use utils::{bits::FromBits, iter::xor};

pub struct Kos15Receiver<S = state::Initialized>(S)
where
    S: state::ReceiverState;

impl Default for Kos15Receiver {
    fn default() -> Self {
        let rng = ChaCha12Rng::from_entropy();
        Self::new_with_rng(rng)
    }
}

impl Kos15Receiver {
    pub fn new_from_seed(seed: [u8; 32]) -> Self {
        let rng = ChaCha12Rng::from_seed(seed);
        Self::new_with_rng(rng)
    }

    pub fn base_setup(
        mut self,
    ) -> Result<(Kos15Receiver<state::BaseSetup>, BaseSenderSetupWrapper), ExtReceiverCoreError>
    {
        let base_setup_message = self.0.base_sender.setup(&mut self.0.rng)?;
        let kos_receiver = Kos15Receiver(state::BaseSetup {
            rng: self.0.rng,
            base_sender: self.0.base_sender,
            cointoss_share: self.0.cointoss_share,
            commitment: self.0.commitment,
        });
        let message = BaseSenderSetupWrapper {
            setup: base_setup_message,
            cointoss_commit: blake3(&self.0.cointoss_share),
        };
        Ok((kos_receiver, message))
    }

    pub fn store_commitment(&mut self, commitment: [u8; 32]) {
        self.0.commitment = Some(commitment);
    }

    fn new_with_rng(mut rng: ChaCha12Rng) -> Self {
        let cointoss_share = rng.gen();
        Self(state::Initialized {
            base_sender: BaseSender::default(),
            rng,
            cointoss_share,
            commitment: None,
        })
    }
}

impl Kos15Receiver<state::BaseSetup> {
    pub fn base_send(
        mut self,
        setup_msg: BaseReceiverSetupWrapper,
    ) -> Result<(Kos15Receiver<state::BaseSend>, BaseSenderPayloadWrapper), ExtReceiverCoreError>
    {
        let mut seeds: Vec<[Block; 2]> = Vec::with_capacity(BASE_COUNT);
        for _ in 0..BASE_COUNT {
            seeds.push([
                Block::random(&mut self.0.rng),
                Block::random(&mut self.0.rng),
            ]);
        }

        let base_send = self.0.base_sender.send(&seeds, setup_msg.setup)?;
        let rngs = seed_rngs_from_nested(&seeds);
        let mut cointoss_random = [0_u8; 32];
        xor(
            &setup_msg.cointoss_share,
            &self.0.cointoss_share,
            &mut cointoss_random,
        );

        let kos_receiver = Kos15Receiver(state::BaseSend {
            rng: self.0.rng,
            rngs,
            cointoss_random,
            commitment: self.0.commitment,
        });
        let message = BaseSenderPayloadWrapper {
            payload: base_send,
            cointoss_share: self.0.cointoss_share,
        };

        Ok((kos_receiver, message))
    }
}

impl Kos15Receiver<state::BaseSend> {
    /// Set up receiver for OT extension
    ///
    /// * `choices` - The receiver's choices for the extended OT
    pub fn extension_setup(
        mut self,
        choices: &[bool],
    ) -> Result<(Kos15Receiver<state::Setup>, ExtReceiverSetup), ExtReceiverCoreError> {
        let (table, choices, message) = extension_setup_from(
            &choices,
            &mut self.0.rng,
            &mut self.0.rngs,
            &self.0.cointoss_random,
        )?;
        let receiver = Kos15Receiver(state::Setup { table, choices });
        Ok((receiver, message))
    }

    /// Set up receiver for random OT extension
    ///
    /// * `count` - The number of OTs which the receiver prepares. Needs to agree with the
    ///             sender
    pub fn rand_extension_setup(
        mut self,
        count: usize,
    ) -> Result<(Kos15Receiver<state::RandSetup>, ExtReceiverSetup), ExtReceiverCoreError> {
        let mut rand_choices = vec![false; count];
        self.0.rng.fill::<[bool]>(&mut rand_choices);
        let (table, choices, message) = extension_setup_from(
            &rand_choices,
            &mut self.0.rng,
            &mut self.0.rngs,
            &self.0.cointoss_random,
        )?;
        let init_ot_number = choices.len();
        let receiver = Kos15Receiver(state::RandSetup {
            rng: self.0.rng,
            table,
            rand_choices,
            derandomized: Vec::new(),
            sender_output_tape: Vec::new(),
            choices_tape: Vec::new(),
            commitment: self.0.commitment,
            init_ot_number,
        });
        Ok((receiver, message))
    }
}

impl Kos15Receiver<state::Setup> {
    pub fn receive(
        &mut self,
        payload: ExtSenderPayload,
    ) -> Result<Vec<Block>, ExtReceiverCoreError> {
        if payload.ciphertexts.len() > self.0.choices.len() {
            return Err(ExtReceiverCoreError::InvalidPayloadSize);
        }
        let (output, _) = receive_from(&mut self.0.table, &mut self.0.choices, &payload)?;
        Ok(output)
    }

    pub fn is_complete(&self) -> bool {
        self.0.choices.is_empty()
    }

    pub fn split(&mut self, split_at: usize) -> Result<Self, ExtReceiverCoreError> {
        Ok(Kos15Receiver(state::Setup {
            table: self.0.table.split_off_rows(split_at)?,
            choices: self.0.choices.split_off(split_at),
        }))
    }
}

impl Kos15Receiver<state::RandSetup> {
    /// At this point, the Receiver has a bunch of random bits. Each bit `r` has
    /// a corresponding symmetric key, i.e. if `r` == 0 then the key is `K_0`, but
    /// if `r` == 1 then the key is `K_1`.
    /// The Sender has both symmetric keys `K_0` and `K_1`, but he does not know
    /// `r`. He has two labels, only one of which the Receiver must learn.
    /// If the Receiver's choice bit matches `r`, then he signals "0", meaning
    /// "use `K_0` to encrypt label_0 and use `K_1` to encrypt label_1", otherwise
    /// he signals "1", meaning "use `K_1` to encrypt label_0 and `K_0` to encrypt
    /// label_1".
    /// By so signalling, the Receiver is "derandomizing" the Oblivious Transfer.
    pub fn derandomize(
        &mut self,
        choices: &[bool],
    ) -> Result<ExtDerandomize, ExtReceiverCoreError> {
        if choices.len() > self.0.rand_choices.len() {
            return Err(ExtReceiverCoreError::InvalidChoiceLength);
        }

        let random_choices: Vec<bool> = self.0.rand_choices.drain(..choices.len()).collect();
        let flip: Vec<bool> = random_choices
            .iter()
            .zip(choices)
            .map(|(a, b)| a ^ b)
            .collect();

        self.0.derandomized.extend_from_slice(choices);
        Ok(ExtDerandomize { flip })
    }

    /// (After derandomization we are in the Standard OT mode) Receives
    /// encrypted OT messages.
    pub fn receive(
        &mut self,
        payload: ExtSenderPayload,
    ) -> Result<Vec<Block>, ExtReceiverCoreError> {
        if payload.ciphertexts.len() != self.0.derandomized.len() {
            return Err(ExtReceiverCoreError::CiphertextCountWrong);
        }

        let (output, choices) =
            receive_from(&mut self.0.table, &mut self.0.derandomized, &payload)?;
        self.0
            .sender_output_tape
            .extend_from_slice(&payload.ciphertexts);
        self.0.choices_tape.extend_from_slice(&choices);
        Ok(output)
    }

    pub fn is_complete(&self) -> bool {
        self.0.derandomized.is_empty() && self.0.rand_choices.is_empty()
    }

    /// Returns the number of remaining OTs which have not been consumed yet
    pub fn remaining(&self) -> usize {
        self.0.rand_choices.len()
    }

    pub fn split(&mut self, split_at: usize) -> Result<Self, ExtReceiverCoreError> {
        if !self.0.derandomized.is_empty() {
            return Err(ExtReceiverCoreError::SplitAfterDerand);
        }

        Ok(Kos15Receiver(state::RandSetup {
            rng: self.0.rng.clone(),
            table: self.0.table.split_off_rows(split_at)?,
            rand_choices: self.0.rand_choices.split_off(split_at),
            derandomized: Vec::new(),
            sender_output_tape: Vec::new(),
            choices_tape: Vec::new(),
            commitment: self.0.commitment,
            init_ot_number: self.0.init_ot_number,
        }))
    }

    /// Implements a weak version of verifiable OT
    ///
    /// This function is an implementation of verifiable OT for the sender only. It uses a
    /// commitment and reveal of the sender to replay the OT session between sender and
    /// receiver and allows the receiver to check that the sender acted correctly.
    ///
    /// The sender commits in the beginning to the seed of his RNG. During the session the receiver
    /// records all ciphertext blocks received by the sender and his choices. Afterwards in the
    /// reveal phase the sender sends the RNG seed and the receiver, who knows what all the expected
    /// plaintext OT messages are, can replay the whole session and check for correctness.
    pub fn verify(
        self,
        reveal: ExtSenderReveal,
        expected_sender_input: &[[Block; 2]],
    ) -> Result<(), CommittedOTError> {
        // Check commitment for correctness
        let hash = [reveal.seed.as_slice(), reveal.salt.as_slice()].concat();

        if let Some(commitment) = self.0.commitment {
            if blake3(&hash) != commitment {
                return Err(CommittedOTError::CommitmentCheck);
            }
        } else {
            return Err(CommittedOTError::NoCommitment);
        }

        // We now instantiate sender and receiver from the given seeds,
        // replay the session and check for message correctness of the sender
        let sender = Kos15Sender::new_from_seed(reveal.seed);
        let receiver = Kos15Receiver::new_from_seed(self.0.rng.get_seed());

        let (receiver, r_message) = receiver.base_setup()?;
        let (sender, s_message) = sender.base_setup(r_message)?;

        let (receiver, r_message) = receiver.base_send(s_message)?;
        let sender = sender.base_receive(r_message)?;

        let (mut receiver, r_message) = receiver.rand_extension_setup(self.0.init_ot_number)?;
        let mut sender = sender.rand_extension_setup(self.0.init_ot_number, r_message)?;

        let (mut sender, mut receiver) = if reveal.offset > 0 {
            (sender.split(reveal.offset)?, receiver.split(reveal.offset)?)
        } else {
            (sender, receiver)
        };

        let derandomized = receiver.derandomize(&self.0.choices_tape)?;
        let sender_output = sender.rand_send(expected_sender_input, derandomized)?;

        if sender_output.ciphertexts.len() != self.0.sender_output_tape.len() {
            return Err(CommittedOTError::IncompleteTape);
        }

        for k in 0..sender_output.ciphertexts.len() {
            if sender_output.ciphertexts[k] != self.0.sender_output_tape[k] {
                return Err(CommittedOTError::Verify);
            }
        }

        Ok(())
    }
}

fn receive_from(
    table: &mut KosMatrix,
    choices: &mut Vec<bool>,
    payload: &ExtSenderPayload,
) -> Result<(Vec<Block>, Vec<bool>), ExtReceiverCoreError> {
    let consumed_choices: Vec<bool> = choices.drain(..payload.ciphertexts.len()).collect();

    let consumed_table: KosMatrix = table.split_off_rows_reverse(consumed_choices.len())?;

    let values = decrypt_values::<Aes128>(
        &Aes128::new_from_slice(&[0u8; 16]).unwrap(),
        &payload.ciphertexts,
        consumed_table.inner(),
        &consumed_choices,
    );
    Ok((values, consumed_choices))
}

fn extension_setup_from(
    choices: &[bool],
    rng: &mut ChaCha12Rng,
    rngs: &mut Vec<[ChaCha12Rng; 2]>,
    cointoss_random: &[u8; 32],
) -> Result<(KosMatrix, Vec<bool>, ExtReceiverSetup), ExtReceiverCoreError> {
    // For performance purposes we require that choice + padding is a multiple of 8 * LANE_COUNT.
    // Note that this padding is never used for OTs on the sender side.
    //
    // For example in the case of x86_64 simd implementation of matrix transposition, LANE_COUNT =
    // 32, so we need the choices to be a multiple 256 = 8 * 32. Adding any additional padding
    // will not improve the performance.
    //
    // We also add minimum 256 extra bits which will be sacrificed for the KOS15 check as part of the
    // KOS15 protocol.
    //
    // How does the padding affect the drainage of rows after the transpose? When padding with
    // e.g. 256 extra bits, these are 32 extra bytes in u8 encoding, so it will increase the
    // KOS extension matrix by 32 columns. After transposition these additional columns turn
    // into additional rows, namely 32 * 8, where the factor 8 comes from the fact that it is a
    // bit-level transpose. This is why, in the end we will have to drain 256 rows in total.
    let padding = calc_padding(choices.len());
    let mut padding_values = vec![false; padding];
    rng.fill::<[bool]>(&mut padding_values);

    // Extend choice bits
    let mut r_bool = choices.to_vec();
    r_bool.extend(&padding_values);
    let r: Vec<u8> = Vec::from_msb0(r_bool.iter().copied());
    let ncols = r_bool.len();

    let row_length = ncols / 8;
    let num_elements = BASE_COUNT * row_length;
    let mut ts: KosMatrix = KosMatrix::new(vec![0_u8; num_elements], row_length)?;
    let mut gs: KosMatrix = KosMatrix::new(vec![0_u8; num_elements], row_length)?;

    // Note that for each row j of the matrix gs which will be sent to Sender,
    // Sender knows either rng[0] or rng[1] depending on his choice bit during
    // base OT. If he knows rng[1] then he will XOR it with gs[j] and get a
    // row ( ts[j] ^ r ). But if he knows rng[0] then his row will be ts[j].
    for (j, (row_gs, row_ts)) in gs.iter_rows_mut().zip(ts.iter_rows_mut()).enumerate() {
        rngs[j][0].fill_bytes(row_ts);
        rngs[j][1].fill_bytes(row_gs);
        row_gs
            .iter_mut()
            .zip(row_ts.iter())
            .zip(r.iter())
            .for_each(|((g, t), r)| *g ^= *t ^ *r);
    }

    // After Sender transposes his matrix, he will have a table S such that
    // for each row j:
    // self.table[j] = S[j], if our choice bit was 0 or
    // self.table[j] = S[j] ^ delta, if our choice bit was 1
    // (note that delta is known only to Sender)
    ts.transpose_bits()?;

    // Perform KOS15 check
    let mut rng = ChaCha12Rng::from_seed(*cointoss_random);
    let kos15check_results = kos15_check_receiver(&mut rng, &ts, &r_bool);

    // Remove padding and the last 256 rows which were sacrificed due to the KOS check
    ts.split_off_rows(ts.rows() - padding)?;

    let message = ExtReceiverSetup {
        count: choices.len(),
        table: gs.into_inner(),
        x: kos15check_results[0].into(),
        t0: kos15check_results[1].into(),
        t1: kos15check_results[2].into(),
    };
    Ok((ts, choices.to_vec(), message))
}
