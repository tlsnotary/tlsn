use crate::{
    msgs::ot as msgs,
    ot::base::{
        dh_ot::{decrypt_input, hash_point, ReceiverCoreError, DOMAIN_SEP},
        ReceiverState,
    },
    Block,
};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar,
};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};

pub struct DhOtReceiver {
    /// The current state of the protocol
    state: ReceiverState,
    /// The transcript of the protocol so far
    transcript: Transcript,
    /// The keys used to decrypt the sender's responses
    decryption_keys: Option<Vec<Block>>,
    /// The bits that this receiver picked
    choices: Option<Vec<bool>>,
}

impl Default for DhOtReceiver {
    fn default() -> Self {
        DhOtReceiver {
            state: ReceiverState::Initialized,
            transcript: Transcript::new(DOMAIN_SEP),
            decryption_keys: None,
            choices: None,
        }
    }
}

fn check_state(expected: ReceiverState, received: ReceiverState) -> Result<(), ReceiverCoreError> {
    if expected != received {
        Err(ReceiverCoreError::BadState(
            format!("{:?}", expected),
            format!("{:?}", received),
        ))
    } else {
        Ok(())
    }
}

impl DhOtReceiver {
    /// Returns current state of this OT protocol
    pub fn state(&self) -> ReceiverState {
        self.state
    }

    /// Constructs all the blinded choices, given the sender's pubkey
    pub fn setup<R: CryptoRng + RngCore>(
        &mut self,
        rng: &mut R,
        choices: &[bool],
        sender_setup: msgs::SenderSetup,
    ) -> Result<msgs::ReceiverSetup, ReceiverCoreError> {
        check_state(ReceiverState::Initialized, self.state)?;

        // Log the sending of the pubkey
        self.transcript
            .append_message(b"pubkey", sender_setup.public_key.compress().as_bytes());

        // point_table is A in [ref1]
        let public_key = sender_setup.public_key;
        let point_table = RistrettoBasepointTable::create(&public_key);

        // Construct the return value and compute the decryption keys in advance for the sender's
        // response ciphertexts
        let (blinded_choices, decryption_keys): (Vec<RistrettoPoint>, Vec<Block>) = choices
            .iter()
            .map(|c| {
                let b = Scalar::random(rng);
                // blinded_choice is B in [ref1]
                let blinded_choice = if *c {
                    public_key + &b * &*RISTRETTO_BASEPOINT_TABLE
                } else {
                    &b * &*RISTRETTO_BASEPOINT_TABLE
                };

                // Witness the blinded choice in the transcript
                self.transcript
                    .append_message(b"B", blinded_choice.compress().as_bytes());

                // Construct a tweak to domain-separate the ristretto point hashes
                let mut tweak = [0u8; 16];
                self.transcript.challenge_bytes(b"tweak", &mut tweak);

                // dec_key is k_r in [ref1] == hash(A^b)
                let dec_key = hash_point(&(&b * &point_table), &tweak);
                // we send the choice values to the Sender and keep the h values
                (blinded_choice, dec_key)
            })
            .unzip();

        // Update the state
        self.decryption_keys = Some(decryption_keys);
        self.choices = Some(Vec::from(choices));
        self.state = ReceiverState::Setup;

        // Return the blinded choices
        Ok(msgs::ReceiverSetup { blinded_choices })
    }

    /// Decrypts the OT sender's ciphertexts
    pub fn receive(
        &mut self,
        payload: msgs::SenderPayload,
    ) -> Result<Vec<Block>, ReceiverCoreError> {
        check_state(ReceiverState::Setup, self.state)?;

        let keys = self.decryption_keys.as_ref().unwrap();
        let selected_inputs: Result<Vec<Block>, ReceiverCoreError> = self
            .choices
            .as_ref()
            .unwrap()
            .iter()
            .zip(keys)
            .zip(payload.ciphertexts.iter())
            .map(|((&c, &key), [ct0, ct1])| {
                // Select an encrypted value based on the choices bit
                let ct = if c { ct1 } else { ct0 };
                // Decrypt it with the corresponding key
                decrypt_input(key, *ct)
            })
            .collect();

        // Update the state regardless of whether this OT succeeded or not
        self.state = ReceiverState::Complete;

        selected_inputs
    }
}
