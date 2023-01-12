use crate::{
    msgs::ot as msgs,
    ot::base::{
        dh_ot::{encrypt_input, hash_point, DhOtCiphertext, DOMAIN_SEP},
        SenderCoreError, SenderState,
    },
    Block,
};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE, ristretto::RistrettoPoint, scalar::Scalar,
};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};

pub struct DhOtSender {
    /// The current state of the protocol
    state: SenderState,
    /// The transcript of the protocol so far
    transcript: Transcript,
    /// The private_key is random `a` in [ref1]
    private_key: Option<Scalar>,
    // The public_key is `A == g^a` in [ref1]
    public_key: Option<RistrettoPoint>,
}

impl Default for DhOtSender {
    fn default() -> Self {
        DhOtSender {
            private_key: None,
            public_key: None,
            state: SenderState::Initialized,
            transcript: Transcript::new(DOMAIN_SEP),
        }
    }
}

fn check_state(expected: SenderState, received: SenderState) -> Result<(), SenderCoreError> {
    if expected != received {
        Err(SenderCoreError::BadState(
            format!("{:?}", expected),
            format!("{:?}", received),
        ))
    } else {
        Ok(())
    }
}

impl DhOtSender {
    /// Generates the keypair to be used by the sender for this OT
    pub fn setup<R: CryptoRng + RngCore>(
        &mut self,
        rng: &mut R,
    ) -> Result<msgs::SenderSetup, SenderCoreError> {
        check_state(SenderState::Initialized, self.state)?;

        // Randomly sample a private key
        let private_key = Scalar::random(rng);
        // Compute the pubkey A = aG where G is a generator
        let public_key = &private_key * &RISTRETTO_BASEPOINT_TABLE;

        // Update the state
        self.private_key = Some(private_key);
        self.public_key = Some(public_key);
        self.state = SenderState::Setup;

        // Log the sending of the pubkey
        self.transcript
            .append_message(b"pubkey", public_key.compress().as_bytes());

        // Return the pubkey
        Ok(msgs::SenderSetup { public_key })
    }

    /// For each i, sends `inputs[i][0]` or `inputs[i][1]` base on the corresponding receiver's
    /// choices. Panics if `inputs.len() != receivers_choices.blinded_choices.len()`.
    pub fn send(
        &mut self,
        inputs: &[[Block; 2]],
        receivers_choices: msgs::ReceiverSetup,
    ) -> Result<msgs::SenderPayload, SenderCoreError> {
        // This sender needs to be ready to send, and the number of inputs needs to be equal to the
        // number of choices
        check_state(SenderState::Setup, self.state)?;

        assert_eq!(
            inputs.len(),
            receivers_choices.blinded_choices.len(),
            "num. OT choices doesn't match num. inputs"
        );

        let private_key = self.private_key.unwrap();

        // ys is A^a in [ref1]
        let ys = private_key * self.public_key.unwrap();

        // Compute and collect all the OT ciphertexts
        let ciphertexts: Vec<[DhOtCiphertext; 2]> = inputs
            .iter()
            .zip(receivers_choices.blinded_choices)
            .map(|(input, receivers_choice)| {
                // Witness the receiver's choice in the transcript
                self.transcript
                    .append_message(b"B", &*receivers_choice.compress().as_bytes());

                // Construct a tweak to domain-separate the ristretto point hashes
                let mut tweak = [0u8; 16];
                self.transcript.challenge_bytes(b"tweak", &mut tweak);

                // yr is B^a in [ref1]
                let yr = private_key * receivers_choice;
                let k0 = hash_point(&yr, &tweak).into();
                // yr - ys == (B/A)^a in [ref1]
                let k1 = hash_point(&(yr - ys), &tweak).into();

                [encrypt_input(k0, input[0]), encrypt_input(k1, input[1])]
            })
            .collect();

        // Update the state and return the ciphertexts
        self.state = SenderState::Complete;
        Ok(msgs::SenderPayload { ciphertexts })
    }
}
