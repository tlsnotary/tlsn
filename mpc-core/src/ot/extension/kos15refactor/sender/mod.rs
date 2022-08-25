pub mod error;
mod state;

use crate::{
    msgs::ot::{
        BaseReceiverSetupWrapper, BaseSenderPayloadWrapper, BaseSenderSetupWrapper, ExtDerandomize,
        ExtReceiverSetup, ExtSenderPayload,
    },
    ot::DhOtReceiver as BaseReceiver,
    utils::{sha256, xor},
    Block,
};
use aes::{Aes128, NewBlockCipher};
use error::ExtSenderCoreError;
use rand::Rng;
use rand_chacha::ChaCha12Rng;
use rand_core::{RngCore, SeedableRng};
use state::SenderState;
pub use state::{BaseReceive, BaseSetup, Initialized, Setup};

use super::{
    matrix::{Error as MatrixError, KosMatrix},
    utils::{calc_padding, encrypt_values, kos15_check_sender, seed_rngs},
    BASE_COUNT,
};

#[derive(Debug)]
pub struct Kos15Sender<S = Initialized>(pub S)
where
    S: SenderState;

impl Default for Kos15Sender {
    fn default() -> Self {
        let mut rng = ChaCha12Rng::from_entropy();

        let cointoss_share = rng.gen();
        let mut base_choices = vec![false; BASE_COUNT];
        rng.fill::<[bool]>(&mut base_choices);

        Self(Initialized {
            rng,
            base_receiver: BaseReceiver::default(),
            base_choices,
            cointoss_share,
        })
    }
}

impl Kos15Sender {
    pub fn base_setup(
        mut self,
        setup_msg: BaseSenderSetupWrapper,
    ) -> Result<(Kos15Sender<BaseSetup>, BaseReceiverSetupWrapper), ExtSenderCoreError> {
        let message = BaseReceiverSetupWrapper {
            setup: self.0.base_receiver.setup(
                &mut self.0.rng,
                &self.0.base_choices,
                setup_msg.setup,
            )?,
            cointoss_share: self.0.cointoss_share,
        };
        let kos_15_sender = Kos15Sender::<BaseSetup>(BaseSetup {
            receiver_cointoss_commit: setup_msg.cointoss_commit,
            base_receiver: self.0.base_receiver,
            base_choices: self.0.base_choices,
            cointoss_share: self.0.cointoss_share,
        });
        Ok((kos_15_sender, message))
    }
}

impl Kos15Sender<BaseSetup> {
    pub fn base_receive(
        mut self,
        setup_msg: BaseSenderPayloadWrapper,
    ) -> Result<Kos15Sender<BaseReceive>, ExtSenderCoreError> {
        let sender_blocks = self.0.base_receiver.receive(setup_msg.payload)?;
        let rngs = seed_rngs(&sender_blocks);

        // Check the decommitment for the other party's share
        if sha256(&setup_msg.cointoss_share) != self.0.receiver_cointoss_commit {
            return Err(ExtSenderCoreError::CommitmentCheckFailed);
        }

        let mut cointoss_random = [0_u8; 32];
        xor(
            &setup_msg.cointoss_share,
            &self.0.cointoss_share,
            &mut cointoss_random,
        );

        let kos_15_sender = Kos15Sender::<BaseReceive>(BaseReceive {
            seeds: sender_blocks,
            cointoss_random,
            base_choices: self.0.base_choices,
            rngs,
        });

        Ok(kos_15_sender)
    }
}

impl Kos15Sender<BaseReceive> {
    pub fn extension_setup(
        mut self,
        setup_msg: ExtReceiverSetup,
    ) -> Result<Kos15Sender<Setup>, ExtSenderCoreError> {
        let ncols_unpadded = setup_msg.ncols;

        if ncols_unpadded > 1_000_000 {
            return Err(ExtSenderCoreError::InvalidInputLength);
        }

        let expected_padding = calc_padding(ncols_unpadded);
        let ncols = setup_msg.table.len() / BASE_COUNT * 8;

        if ncols != ncols_unpadded + expected_padding {
            return Err(ExtSenderCoreError::InvalidPadding);
        }

        let row_length = ncols / 8;
        let num_elements = BASE_COUNT * row_length;

        let us = KosMatrix::new(setup_msg.table, row_length)?;
        let mut qs = KosMatrix::new(vec![0u8; num_elements], row_length)?;

        for (j, (row_qs, row_us)) in qs.iter_rows_mut().zip(us.iter_rows()).enumerate() {
            self.0.rngs[j].fill_bytes(row_qs);
            if self.0.base_choices[j] {
                row_qs
                    .iter_mut()
                    .zip(row_us.iter())
                    .for_each(|(q, u)| *q ^= *u);
            }
        }
        qs.transpose_bits()?;

        // Seeding with a value from cointoss so that neither party could influence
        // the randomness
        let mut rng = ChaCha12Rng::from_seed(self.0.cointoss_random);

        // Perform KOS15 sender check
        if !kos15_check_sender(
            &mut rng,
            &qs,
            ncols,
            &setup_msg.x,
            &setup_msg.t0,
            &setup_msg.t1,
            &self.0.base_choices,
        ) {
            return Err(ExtSenderCoreError::ConsistencyCheckFailed);
        };

        // Remove additional rows introduced by padding
        qs.split_off_rows(qs.rows() - expected_padding)?;

        let kos15_sender = Kos15Sender::<Setup>(Setup {
            table: qs,
            count: ncols_unpadded,
            sent: 0,
            base_choices: self.0.base_choices,
        });

        Ok(kos15_sender)
    }
}
impl Kos15Sender<Setup> {
    pub fn send(&mut self, inputs: &[[Block; 2]]) -> Result<ExtSenderPayload, ExtSenderCoreError> {
        self.send_from(inputs, None)
    }

    pub fn rand_send(
        &mut self,
        inputs: &[[Block; 2]],
        derandomize: ExtDerandomize,
    ) -> Result<ExtSenderPayload, ExtSenderCoreError> {
        self.send_from(inputs, Some(derandomize))
    }

    fn send_from(
        &mut self,
        inputs: &[[Block; 2]],
        derandomize: Option<ExtDerandomize>,
    ) -> Result<ExtSenderPayload, ExtSenderCoreError> {
        if self.0.sent + inputs.len() > self.0.count {
            return Err(ExtSenderCoreError::InvalidInputLength);
        }

        let consumed_table: KosMatrix = self.0.table.split_off_rows_reverse(inputs.len())?;

        // Check that all the input lengths are equal
        if inputs.len() != consumed_table.rows() {
            return Err(ExtSenderCoreError::InvalidInputLength);
        }

        if let Some(ref inner) = derandomize {
            if inner.flip.len() != consumed_table.rows() {
                return Err(ExtSenderCoreError::InvalidInputLength);
            }
        }

        let ciphertexts = encrypt_values(
            &Aes128::new_from_slice(&[0u8; 16]).unwrap(),
            inputs,
            &consumed_table.inner(),
            &self.0.base_choices,
            derandomize.map(|inner| inner.flip),
        );

        self.0.sent += inputs.len();
        Ok(ExtSenderPayload { ciphertexts })
    }

    pub fn is_complete(&self) -> bool {
        self.0.sent == self.0.count
    }
}
