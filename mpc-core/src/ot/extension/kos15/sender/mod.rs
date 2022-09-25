pub mod error;
pub mod state;

use std::sync::{Arc, Mutex};

use crate::{
    msgs::ot::{
        BaseReceiverSetupWrapper, BaseSenderPayloadWrapper, BaseSenderSetupWrapper, ExtDerandomize,
        ExtReceiverSetup, ExtSenderCommit, ExtSenderDecommit, ExtSenderPayload,
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

use super::{
    matrix::{Error as MatrixError, KosMatrix},
    utils::{calc_padding, encrypt_values, kos15_check_sender, seed_rngs},
    BASE_COUNT,
};

#[derive(Debug)]
pub struct Kos15Sender<S = state::Initialized>(S)
where
    S: state::SenderState;

impl Default for Kos15Sender {
    fn default() -> Self {
        let rng = ChaCha12Rng::from_entropy();
        Self::new_with_rng(rng)
    }
}

impl Kos15Sender {
    pub fn new_with_rng(mut rng: ChaCha12Rng) -> Self {
        let cointoss_share = rng.gen();
        let mut base_choices = vec![false; BASE_COUNT];
        rng.fill::<[bool]>(&mut base_choices);

        Self(state::Initialized {
            rng,
            base_receiver: BaseReceiver::default(),
            base_choices,
            cointoss_share,
        })
    }

    pub fn new_from_seed(seed: [u8; 32]) -> Self {
        let rng = ChaCha12Rng::from_seed(seed);
        Self::new_with_rng(rng)
    }

    pub fn commit_to_seed(&self) -> ExtSenderCommit {
        ExtSenderCommit(sha256(&self.0.rng.get_seed()))
    }

    pub fn base_setup(
        mut self,
        setup_msg: BaseSenderSetupWrapper,
    ) -> Result<(Kos15Sender<state::BaseSetup>, BaseReceiverSetupWrapper), ExtSenderCoreError> {
        let message = BaseReceiverSetupWrapper {
            setup: self.0.base_receiver.setup(
                &mut self.0.rng,
                &self.0.base_choices,
                setup_msg.setup,
            )?,
            cointoss_share: self.0.cointoss_share,
        };
        let kos_15_sender = Kos15Sender(state::BaseSetup {
            rng: self.0.rng,
            receiver_cointoss_commit: setup_msg.cointoss_commit,
            base_receiver: self.0.base_receiver,
            base_choices: self.0.base_choices,
            cointoss_share: self.0.cointoss_share,
        });
        Ok((kos_15_sender, message))
    }
}

impl Kos15Sender<state::BaseSetup> {
    pub fn base_receive(
        mut self,
        setup_msg: BaseSenderPayloadWrapper,
    ) -> Result<Kos15Sender<state::BaseReceive>, ExtSenderCoreError> {
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

        let kos_15_sender = Kos15Sender(state::BaseReceive {
            rng: self.0.rng,
            cointoss_random,
            base_choices: self.0.base_choices,
            rngs,
        });

        Ok(kos_15_sender)
    }
}

impl Kos15Sender<state::BaseReceive> {
    pub fn extension_setup(
        mut self,
        setup_msg: ExtReceiverSetup,
    ) -> Result<Kos15Sender<state::Setup>, ExtSenderCoreError> {
        let (table, ncols_unpadded) = extension_setup_from(
            &mut self.0.rngs,
            &self.0.base_choices,
            setup_msg,
            &self.0.cointoss_random,
        )?;
        Ok(Kos15Sender(state::Setup {
            rng: self.0.rng,
            table,
            count: ncols_unpadded,
            sent: 0,
            base_choices: self.0.base_choices,
        }))
    }

    pub fn rand_extension_setup(
        mut self,
        setup_msg: ExtReceiverSetup,
    ) -> Result<Kos15Sender<state::RandSetup>, ExtSenderCoreError> {
        let (table, ncols_unpadded) = extension_setup_from(
            &mut self.0.rngs,
            &self.0.base_choices,
            setup_msg,
            &self.0.cointoss_random,
        )?;
        Ok(Kos15Sender(state::RandSetup {
            rng: self.0.rng,
            table,
            count: ncols_unpadded,
            sent: 0,
            base_choices: self.0.base_choices,
            tape: Vec::new(),
            offset: 0,
            shutdown: Arc::new(Mutex::new(false)),
        }))
    }
}

impl Kos15Sender<state::Setup> {
    pub fn send(&mut self, inputs: &[[Block; 2]]) -> Result<ExtSenderPayload, ExtSenderCoreError> {
        send_from(
            &mut self.0.count,
            &mut self.0.sent,
            &mut self.0.table,
            &self.0.base_choices,
            inputs,
            None,
        )
    }

    pub fn split(&mut self, split_at: usize) -> Result<Self, ExtSenderCoreError> {
        let split_table = self.0.table.split_off_rows(split_at)?;
        let rows = split_table.rows();
        self.0.count -= rows;

        Ok(Kos15Sender(state::Setup {
            rng: self.0.rng.clone(),
            table: split_table,
            count: rows,
            sent: 0,
            base_choices: self.0.base_choices.clone(),
        }))
    }

    pub fn is_complete(&self) -> bool {
        self.0.sent == self.0.count
    }
}

impl Kos15Sender<state::RandSetup> {
    pub fn rand_send(
        &mut self,
        inputs: &[[Block; 2]],
        derandomize: ExtDerandomize,
    ) -> Result<ExtSenderPayload, ExtSenderCoreError> {
        if *self
            .0
            .shutdown
            .lock()
            .map_err(|_| ExtSenderCoreError::Poison)?
            == true
        {
            return Err(ExtSenderCoreError::Shutdown);
        }

        let result = send_from(
            &mut self.0.count,
            &mut self.0.sent,
            &mut self.0.table,
            &self.0.base_choices,
            inputs,
            Some(derandomize),
        );

        if result.is_ok() {
            self.0.tape.extend_from_slice(inputs);
        }
        result
    }

    pub fn split(&mut self, split_at: usize) -> Result<Self, ExtSenderCoreError> {
        if *self
            .0
            .shutdown
            .lock()
            .map_err(|_| ExtSenderCoreError::Poison)?
            == true
        {
            return Err(ExtSenderCoreError::Shutdown);
        }

        let split_table = self.0.table.split_off_rows(split_at)?;
        let rows = split_table.rows();
        self.0.count -= rows;

        Ok(Kos15Sender(state::RandSetup {
            rng: self.0.rng.clone(),
            table: split_table,
            count: rows,
            sent: 0,
            base_choices: self.0.base_choices.clone(),
            tape: Vec::new(),
            offset: self.0.offset + split_at,
            shutdown: Arc::clone(&self.0.shutdown),
        }))
    }

    pub fn is_complete(&self) -> bool {
        self.0.sent == self.0.count
    }

    pub fn decommit(self) -> Result<ExtSenderDecommit, ExtSenderCoreError> {
        *self
            .0
            .shutdown
            .lock()
            .map_err(|_| ExtSenderCoreError::Poison)? = true;

        Ok(ExtSenderDecommit {
            seed: self.0.rng.get_seed(),
            tape: self.0.tape,
        })
    }
}

fn send_from(
    count: &mut usize,
    sent: &mut usize,
    table: &mut KosMatrix,
    base_choices: &[bool],
    inputs: &[[Block; 2]],
    derandomize: Option<ExtDerandomize>,
) -> Result<ExtSenderPayload, ExtSenderCoreError> {
    if *sent + inputs.len() > *count {
        return Err(ExtSenderCoreError::InvalidInputLength);
    }

    let consumed_table: KosMatrix = table.split_off_rows_reverse(inputs.len())?;

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
        consumed_table.inner(),
        base_choices,
        derandomize.map(|inner| inner.flip),
    );

    *sent += inputs.len();
    Ok(ExtSenderPayload { ciphertexts })
}

fn extension_setup_from(
    rngs: &mut [ChaCha12Rng],
    base_choices: &[bool],
    setup_msg: ExtReceiverSetup,
    cointoss_random: &[u8; 32],
) -> Result<(KosMatrix, usize), ExtSenderCoreError> {
    let ncols_unpadded = setup_msg.ncols;

    // Prevent possible DOS attacks
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
        rngs[j].fill_bytes(row_qs);
        if base_choices[j] {
            row_qs
                .iter_mut()
                .zip(row_us.iter())
                .for_each(|(q, u)| *q ^= *u);
        }
    }
    qs.transpose_bits()?;

    // Seeding with a value from cointoss so that neither party could influence
    // the randomness
    let mut rng = ChaCha12Rng::from_seed(*cointoss_random);

    // Perform KOS15 sender check
    if !kos15_check_sender(
        &mut rng,
        &qs,
        ncols,
        &setup_msg.x,
        &setup_msg.t0,
        &setup_msg.t1,
        &base_choices,
    ) {
        return Err(ExtSenderCoreError::ConsistencyCheckFailed);
    };

    // Remove additional rows introduced by padding
    qs.split_off_rows(qs.rows() - expected_padding)?;

    Ok((qs, ncols_unpadded))
}
