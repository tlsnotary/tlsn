mod error;
mod state;

use super::utils::{decrypt_values, kos15_check, seed_rngs};
use super::BASE_COUNT;
use crate::matrix::ByteMatrix;
use crate::msgs::ot::{
    BaseReceiverSetupWrapper, BaseSenderPayloadWrapper, BaseSenderSetupWrapper, ExtDerandomize,
    ExtReceiverSetup, ExtSenderPayload,
};
use crate::ot::DhOtSender as BaseSender;
use crate::utils::{boolvec_to_u8vec, sha256, u8vec_to_boolvec, xor};
use crate::Block;
use aes::{Aes128, NewBlockCipher};
use error::ExtReceiverCoreError;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;
use rand_core::RngCore;
use state::{BaseSend, BaseSetup, Initialized, RecevierState, Setup};

pub struct Kos15Receiver<S = Initialized>(S)
where
    S: RecevierState;

impl Default for Kos15Receiver {
    fn default() -> Self {
        let mut rng = ChaCha12Rng::from_entropy();
        let cointoss_share = rng.gen();
        Self(Initialized {
            base_sender: BaseSender::default(),
            rng,
            cointoss_share,
        })
    }
}

impl Kos15Receiver {
    pub fn base_setup(
        mut self,
    ) -> Result<(Kos15Receiver<BaseSetup>, BaseSenderSetupWrapper), ExtReceiverCoreError> {
        let base_setup_message = self.0.base_sender.setup(&mut self.0.rng)?;
        let kos_receiver = Kos15Receiver::<BaseSetup>(BaseSetup {
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

impl Kos15Receiver<BaseSetup> {
    pub fn base_send(
        mut self,
        setup_msg: BaseReceiverSetupWrapper,
    ) -> Result<(Kos15Receiver<BaseSend>, BaseSenderPayloadWrapper), ExtReceiverCoreError> {
        let mut seeds: Vec<[Block; 2]> = Vec::with_capacity(BASE_COUNT);
        for _ in 0..BASE_COUNT {
            seeds.push([
                Block::random(&mut self.0.rng),
                Block::random(&mut self.0.rng),
            ]);
        }

        let base_send = self.0.base_sender.send(&seeds, setup_msg.setup)?;
        let rngs = seed_rngs(&seeds);
        let mut cointoss_random = [0_u8; 32];
        xor(
            &setup_msg.cointoss_share,
            &self.0.cointoss_share,
            &mut cointoss_random,
        );

        let kos_receiver = Kos15Receiver::<BaseSend>(BaseSend {
            rng: self.0.rng,
            seeds,
            rngs,
            cointoss_random,
            cointoss_share: self.0.cointoss_share,
        });
        let message = BaseSenderPayloadWrapper {
            payload: base_send,
            cointoss_share: self.0.cointoss_share,
        };

        Ok((kos_receiver, message))
    }
}

impl Kos15Receiver<BaseSend> {
    pub fn extension_setup(
        mut self,
        choices: &[bool],
    ) -> Result<(Kos15Receiver<Setup>, ExtReceiverSetup), ExtReceiverCoreError> {
        // For performance purposes we require that choice is a multiple of 2^k for some k. If it
        // is not, we pad. Note that this padding is never used for OTs on the sender side.
        //
        // The x86_64 implementation requires a matrix with minimum row/columns 32, so we need 8*32
        // = 256 choices minimum, thus k should be at least 8. However, making k > 8 will not bring
        // performance gains.
        //
        // We also add 256 extra bits which will be sacrificed for the KOS15 check as part of the
        // KOS15 protocol.
        //
        // These 256 extra bits are 32 extra bytes in u8 encoding, so it will increase the KOS extension
        // matrix by 32 columns. After transposition these additional columns turn into additional rows,
        // namely 32 * 8, where the factor 8 comes from the fact that it is a bit-level transpose.
        // This is why, in the end we will have to drain 256 rows in total.
        let remainder = choices.len() % 256;
        let padding = if remainder == 0 { 256 } else { 512 - remainder };

        // Divide padding by 8 because this is a byte vector and add 1 byte safety margin, when
        // choice.len() is not a multiple of 8
        let mut extra_bytes = vec![0_u8; padding / 8 + 1];
        self.0.rng.fill(&mut extra_bytes[..]);

        // Extend choice bits with the exact amount of extra bits that we need.
        let mut r_bool = choices.to_vec();
        r_bool.extend(u8vec_to_boolvec(&extra_bytes)[..padding].iter());
        let r = boolvec_to_u8vec(&r_bool);
        let ncols = r_bool.len();

        let row_length = ncols / 8;
        let num_elements = BASE_COUNT * row_length;
        let mut ts: ByteMatrix = ByteMatrix::new(vec![0_u8; num_elements], row_length)?;
        let mut gs: ByteMatrix = ByteMatrix::new(vec![0_u8; num_elements], row_length)?;

        // Note that for each row j of the matrix gs which will be sent to Sender,
        // Sender knows either rng[0] or rng[1] depending on his choice bit during
        // base OT. If he knows rng[1] then he will XOR it with gs[j] and get a
        // row ( ts[j] ^ r ). But if he knows rng[0] then his row will be ts[j].
        for (j, (row_gs, row_ts)) in gs.iter_rows_mut().zip(ts.iter_rows_mut()).enumerate() {
            self.0.rngs[j][0].fill_bytes(row_gs);
            self.0.rngs[j][0].fill_bytes(row_ts);
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
        let mut rng = ChaCha12Rng::from_seed(self.0.cointoss_random);
        let kos15check_results = kos15_check(&mut rng, &ts, &r_bool);

        // Remove the last 256 rows which were sacrificed due to the KOS check
        ts.split_off_rows(ts.rows() - 256)?;

        let kos_receiver = Kos15Receiver::<Setup>(Setup {
            table: ts,
            choices: choices.to_vec(),
            derandomized: Vec::new(),
        });
        let message = ExtReceiverSetup {
            ncols: choices.len(),
            table: gs.into_inner(),
            x: kos15check_results[0].into(),
            t0: kos15check_results[1].into(),
            t1: kos15check_results[2].into(),
        };
        Ok((kos_receiver, message))
    }

    pub fn rand_extension_setup(
        mut self,
        choice_len: usize,
    ) -> Result<(Kos15Receiver<Setup>, ExtReceiverSetup), ExtReceiverCoreError> {
        let mut choices = vec![false; choice_len];
        self.0.rng.fill::<[bool]>(&mut choices);
        self.extension_setup(&choices)
    }
}

impl Kos15Receiver<Setup> {
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

    pub fn receive(
        &mut self,
        payload: ExtSenderPayload,
    ) -> Result<Vec<Block>, ExtReceiverCoreError> {
        receive_from(&mut self.0.table, &mut self.0.choices, payload)
    }

    pub fn rand_receive(
        &mut self,
        payload: ExtSenderPayload,
    ) -> Result<Vec<Block>, ExtReceiverCoreError> {
        receive_from(&mut self.0.table, &mut self.0.derandomized, payload)
    }
}

fn receive_from(
    table: &mut ByteMatrix,
    choices: &mut Vec<bool>,
    payload: ExtSenderPayload,
) -> Result<Vec<Block>, ExtReceiverCoreError> {
    if payload.ciphertexts.len() > choices.len() {
        return Err(ExtReceiverCoreError::InvalidPayloadSize);
    }

    let consumed_choices: Vec<bool> = choices.drain(..payload.ciphertexts.len()).collect();

    let consumed_table: ByteMatrix = table.split_off_rows(consumed_choices.len())?;
    let values = decrypt_values::<Aes128>(
        &Aes128::new_from_slice(&[0u8; 16]).unwrap(),
        &payload.ciphertexts,
        consumed_table.inner(),
        &consumed_choices,
    );
    Ok(values)
}
