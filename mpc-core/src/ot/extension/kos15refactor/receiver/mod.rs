mod state;
mod utils;

use self::state::Setup;

use super::BASE_COUNT;
use crate::msgs::ot::{BaseReceiverSetupWrapper, BaseSenderPayloadWrapper, ExtReceiverSetup};
use crate::ot::DhOtSender as BaseSender;
use crate::utils::{boolvec_to_u8vec, sha256, u8vec_to_boolvec, xor};
use crate::Block;
use crate::{msgs::ot::BaseSenderSetupWrapper, ot::ExtReceiverCoreError};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;
use state::{BaseSend, BaseSetup, Initialized, SenderState};
use utils::seed_rngs;

pub struct Kos15Receiver<S = Initialized>(S)
where
    S: SenderState;

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
        base_receiver_setup: BaseReceiverSetupWrapper,
    ) -> Result<(Kos15Receiver<BaseSend>, BaseSenderPayloadWrapper), ExtReceiverCoreError> {
        let mut seeds: Vec<[Block; 2]> = Vec::with_capacity(BASE_COUNT);
        for _ in 0..BASE_COUNT {
            seeds.push([
                Block::random(&mut self.0.rng),
                Block::random(&mut self.0.rng),
            ]);
        }

        let base_send = self.0.base_sender.send(&seeds, base_receiver_setup.setup)?;
        let rngs = seed_rngs(&seeds);
        let mut cointoss_random = [0_u8; 32];
        xor(
            &base_receiver_setup.cointoss_share,
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
        self,
        choice: &[bool],
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
        let remainder = choice.len() % 256;
        let padding = if remainder == 0 { 256 } else { 512 - remainder };

        // Divide padding by 8 because this is a byte vector and add 1 byte safety margin, when
        // choice.len() is not a multiple of 8
        let mut extra_bytes = vec![0_u8; padding / 8 + 1];
        self.0.rng.fill(&mut extra_bytes[..]);

        // Extend choice bits with the exact amount of extra bits that we need.
        let mut r_bool = choice.to_vec();
        r_bool.extend(u8vec_to_boolvec(&extra_bytes)[..padding].iter());
        let r = boolvec_to_u8vec(&r_bool);

        let ncols = r_bool.len();
    }
}
