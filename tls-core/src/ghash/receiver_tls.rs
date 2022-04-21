use super::errors::*;
use super::receiver::*;

#[derive(PartialEq)]
pub enum ReceiverTLSState {
    Initialized,
    // FinishedSent is sent after we send Client/Server Finished
    FinishedSent,
    FinishedReceived,
}

pub struct GhashReceiverTLS {
    parent: GhashReceiver,
    state: ReceiverTLSState,
}

impl GhashReceiverTLS {
    pub fn new(ghash_key_share: u128, blocks: Vec<u128>) -> Self {
        Self {
            parent: GhashReceiver::new(ghash_key_share, blocks),
            state: ReceiverTLSState::Initialized,
        }
    }

    pub fn get_request_for_finished(&mut self) -> Result<Vec<bool>, GhashError> {
        if self.state != ReceiverTLSState::Initialized {
            return Err(GhashError::OutOfORder);
        }
        self.state = ReceiverTLSState::FinishedSent;
        Ok(self.get_ybits_for_finished().concat())
    }

    pub fn process_response_for_finished(
        &mut self,
        response: &Vec<u128>,
    ) -> Result<u128, GhashError> {
        if self.state != ReceiverTLSState::FinishedSent {
            return Err(GhashError::OutOfORder);
        }
        self.state = ReceiverTLSState::FinishedReceived;
        // TODO move flat_to_mxtables to utils to make it accessible
        let mxtable = self.parent.flat_to_mxtables(response)?;
        Ok(self.process_mxtables_for_finished(&mxtable))
    }

    pub fn get_request_for_round1(&mut self) -> Result<Vec<bool>, GhashError> {
        // should should be the first method called after we finish with
        // the Client/Server_Finished
        if self.state != ReceiverTLSState::FinishedReceived {
            return Err(GhashError::OutOfORder);
        }
        self.parent.get_request_for_round1()
    }

    pub fn process_response_for_round1(&mut self, response: &Vec<u128>) -> Result<(), GhashError> {
        if self.state != ReceiverTLSState::FinishedReceived {
            return Err(GhashError::OutOfORder);
        }
        self.parent.process_response_for_round1(response)
    }

    fn get_ybits_for_finished(&mut self) -> Vec<YBits> {
        vec![
            // TODO self.parent.c is private, cant access it
            // need to add to parent a pub method get_power()
            u8vec_to_boolvec(&self.parent.c.powers[&1].to_be_bytes()),
            u8vec_to_boolvec(&self.parent.c.powers[&2].to_be_bytes()),
        ]
    }

    fn process_mxtables_for_finished(&mut self, mxtables: &Vec<MXTable>) -> u128 {
        // the XOR sum of all masked xtables' values plus H^1*H^2 is our share of H^3
        self.parent.c.powers.insert(
            3,
            xor_sum(&mxtables[0])
                ^ xor_sum(&mxtables[1])
                ^ block_mult(self.parent.c.powers[&1], self.parent.c.powers[&2]),
        );
        let ghash_share = block_mult(self.c.blocks[0], self.c.powers[&3])
            ^ block_mult(self.c.blocks[1], self.c.powers[&2])
            ^ block_mult(self.c.blocks[2], self.c.powers[&1]);
        ghash_share
    }
}
