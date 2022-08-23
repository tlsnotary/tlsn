mod error;
mod state;

use crate::{
    matrix::ByteMatrix,
    msgs::ot::{
        BaseReceiverSetupWrapper, BaseSenderPayloadWrapper, BaseSenderSetupWrapper,
        ExtReceiverSetup,
    },
    ot::DhOtReceiver as BaseReceiver,
    utils::{sha256, xor},
};
use error::ExtSenderCoreError;
use rand::Rng;
use rand_chacha::ChaCha12Rng;
use rand_core::{RngCore, SeedableRng};
use state::{BaseReceive, BaseSetup, Initialized, SenderState, Setup};

use super::{
    utils::{kos15_check_sender, seed_rngs},
    BASE_COUNT,
};

pub struct Kos15Sender<S = Initialized>(S)
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

        // Receiver choices were extended with extra padding bytes.
        //
        // - 256 for KOS check
        // - 256 - (...) is the padding calculated from the non-transposed matrix of the receiver
        //   setup
        let rem = ncols_unpadded % 256;
        let pad1 = if rem == 0 { 0 } else { 256 - rem };
        let expected_padding = 256 + pad1;
        let ncols = setup_msg.table.len() / BASE_COUNT * 8;

        if ncols != ncols_unpadded + expected_padding {
            return Err(ExtSenderCoreError::InvalidPadding);
        }

        let row_length = ncols / 8;
        let num_elements = BASE_COUNT * row_length;

        let us = ByteMatrix::new(setup_msg.table, row_length)?;
        let mut qs = ByteMatrix::new(vec![0u8; num_elements * row_length], row_length)?;

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
        });

        Ok(kos15_sender)
    }
}
