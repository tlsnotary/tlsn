pub mod error;
pub mod state;

use super::matrix::{Error as MatrixError, KosMatrix};
use super::utils::{calc_padding, decrypt_values, kos15_check_receiver, seed_rngs_from_nested};
use super::BASE_COUNT;
use crate::msgs::ot::{
    BaseReceiverSetupWrapper, BaseSenderPayloadWrapper, BaseSenderSetupWrapper, ExtDerandomize,
    ExtReceiverSetup, ExtSenderPayload,
};
use crate::ot::DhOtSender as BaseSender;
use crate::utils::{boolvec_to_u8vec, sha256, xor};
use crate::Block;
use aes::{Aes128, NewBlockCipher};
use error::ExtReceiverCoreError;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;
use rand_core::RngCore;

pub struct Kos15Receiver<S = state::Initialized>(S)
where
    S: state::ReceiverState;

impl Default for Kos15Receiver {
    fn default() -> Self {
        let mut rng = ChaCha12Rng::from_entropy();
        let cointoss_share = rng.gen();
        Self(state::Initialized {
            base_sender: BaseSender::default(),
            rng,
            cointoss_share,
        })
    }
}

impl Kos15Receiver {
    pub fn base_setup(
        mut self,
    ) -> Result<(Kos15Receiver<state::BaseSetup>, BaseSenderSetupWrapper), ExtReceiverCoreError>
    {
        let base_setup_message = self.0.base_sender.setup(&mut self.0.rng)?;
        let kos_receiver = Kos15Receiver(state::BaseSetup {
            rng: self.0.rng,
            base_sender: self.0.base_sender,
            cointoss_share: self.0.cointoss_share,
        });
        let message = BaseSenderSetupWrapper {
            setup: base_setup_message,
            cointoss_commit: sha256(&self.0.cointoss_share),
        };
        Ok((kos_receiver, message))
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
        });
        let message = BaseSenderPayloadWrapper {
            payload: base_send,
            cointoss_share: self.0.cointoss_share,
        };

        Ok((kos_receiver, message))
    }
}

impl Kos15Receiver<state::BaseSend> {
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

    pub fn rand_extension_setup(
        mut self,
        choice_len: usize,
    ) -> Result<(Kos15Receiver<state::RandSetup>, ExtReceiverSetup), ExtReceiverCoreError> {
        let mut choices = vec![false; choice_len];
        self.0.rng.fill::<[bool]>(&mut choices);
        let (table, choices, message) = extension_setup_from(
            &choices,
            &mut self.0.rng,
            &mut self.0.rngs,
            &self.0.cointoss_random,
        )?;
        let receiver = Kos15Receiver(state::RandSetup {
            table,
            choices,
            derandomized: Vec::new(),
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
        receive_from(&mut self.0.table, &mut self.0.choices, payload)
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
        derand_choices: &[bool],
    ) -> Result<ExtDerandomize, ExtReceiverCoreError> {
        if derand_choices.len() > self.0.choices.len() {
            return Err(ExtReceiverCoreError::InvalidChoiceLength);
        }

        let random_choices: Vec<bool> = self.0.choices.drain(..derand_choices.len()).collect();
        let flip: Vec<bool> = random_choices
            .iter()
            .zip(derand_choices)
            .map(|(a, b)| a ^ b)
            .collect();

        self.0.derandomized.extend_from_slice(derand_choices);
        Ok(ExtDerandomize { flip })
    }

    pub fn rand_receive(
        &mut self,
        payload: ExtSenderPayload,
    ) -> Result<Vec<Block>, ExtReceiverCoreError> {
        if payload.ciphertexts.len() > self.0.derandomized.len() {
            return Err(ExtReceiverCoreError::NotDerandomized);
        }
        receive_from(&mut self.0.table, &mut self.0.derandomized, payload)
    }

    pub fn is_complete(&self) -> bool {
        self.0.derandomized.is_empty() && self.0.choices.is_empty()
    }

    pub fn split(&mut self, split_at: usize) -> Result<Self, ExtReceiverCoreError> {
        if !self.0.derandomized.is_empty() {
            return Err(ExtReceiverCoreError::SplitAfterDerand);
        }

        Ok(Kos15Receiver(state::RandSetup {
            table: self.0.table.split_off_rows(split_at)?,
            choices: self.0.choices.split_off(split_at),
            derandomized: Vec::new(),
        }))
    }
}

fn receive_from(
    table: &mut KosMatrix,
    choices: &mut Vec<bool>,
    payload: ExtSenderPayload,
) -> Result<Vec<Block>, ExtReceiverCoreError> {
    let consumed_choices: Vec<bool> = choices.drain(..payload.ciphertexts.len()).collect();

    let consumed_table: KosMatrix = table.split_off_rows_reverse(consumed_choices.len())?;

    let values = decrypt_values::<Aes128>(
        &Aes128::new_from_slice(&[0u8; 16]).unwrap(),
        &payload.ciphertexts,
        consumed_table.inner(),
        &consumed_choices,
    );
    Ok(values)
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
    let r = boolvec_to_u8vec(&r_bool);
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
        ncols: choices.len(),
        table: gs.into_inner(),
        x: kos15check_results[0].into(),
        t0: kos15check_results[1].into(),
        t1: kos15check_results[2].into(),
    };
    Ok((ts, choices.to_vec(), message))
}
