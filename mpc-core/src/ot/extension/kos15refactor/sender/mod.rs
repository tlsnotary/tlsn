mod error;
mod state;

use crate::{
    msgs::ot::{BaseReceiverSetupWrapper, BaseSenderPayloadWrapper, BaseSenderSetupWrapper},
    ot::DhOtReceiver as BaseReceiver,
    utils::{sha256, xor},
};
use error::ExtSenderCoreError;
use rand::Rng;
use rand_chacha::ChaCha12Rng;
use rand_core::SeedableRng;
use state::{BaseReceive, BaseSetup, Initialized, SenderState, Setup};

use super::{utils::seed_rngs_one, BASE_COUNT};

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
            count: 0,
            sent: 0,
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
        let rngs = seed_rngs_one(&sender_blocks);

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
            rngs,
        });

        Ok(kos_15_sender)
    }
}
