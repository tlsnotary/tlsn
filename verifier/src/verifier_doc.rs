use super::{Curve, LabelSeed};
use crate::{
    commitment::{Commitment, CommitmentOpening, CommitmentType},
    tls_doc::TLSDoc,
    Error,
};

#[derive(Clone)]
/// The actual document which the verifier will receive
pub struct VerifierDoc {
    version: u8,
    pub tls_doc: TLSDoc,
    /// Notary's signature over the [Signed] portion of this doc
    pub signature: Option<Signature>,

    // TODO: I couldn't think of a good struct where to put the 2 fields below:

    // tx and rx wire labels seeds
    pub labelSeeds: [LabelSeed; 2],

    // For User privacy, the Notary must not know how many individual data commitments there are.
    // For this reason, the User aggregates all his data commitments into this one commitment.
    // This is the only data-related commitment which the Notary is aware of.

    // In essence, this is two hashes concatenated:
    // - the first hash is a hash H(all plaintext commitments from Step 3) of the authdecode
    // diagram https://github.com/tlsnotary/tlsn/blob/authdecode/authdecode/authdecode_diagram.pdf
    // If the User does not use authdecode commitments, the User sends a random value to Notary
    // in Step 3.
    // - the second hash is a hash H(all labelsum commitments from Step 8 of the authdecode diagram,
    // all other non-authdecode commitments). Again, if there are no commitments at all, the User
    // conceals this fact by sending a random value to Notary at this stage.
    pub aggregated_commitment: Vec<u8>,

    // User's commitments to various portions of the TLS transcripts, sorted ascendingly by id
    commitments: Vec<Commitment>,
    // Openings for the commitments or zk proofs about the openings' properties
    commitment_openings: Vec<CommitmentOpening>,
}

impl VerifierDoc {
    // pub fn new() -> Self {
    //     //todo
    // }

    /// verifies the data
    pub fn verify(&self, dns_name: String) -> Result<(), Error> {
        // verify the TLS portion of the doc
        self.tls_doc.verify(dns_name)?;

        self.check_aggregated_commitment()?;

        self.verify_each_commitment()?;

        // TODO do we want to sanity-check the ranges here
        // or leave it to the HTTP parser?

        Ok(())
    }

    /// checks that the aggregated commitment is derived from the smaller commitments
    /// see comments in `[VerifierDoc::aggregated_commitment]`
    fn check_aggregated_commitment(&self) -> Result<(), Error> {
        let authdecode_comm: Vec<&Commitment> = self
            .commitments
            .iter()
            .filter(|c| c.typ == CommitmentType::authdecode)
            .collect();

        // hash all commitments from authdecode Step3
        // see `[CommitmentType::authdecode]`
        let first_hash_preimage = if authdecode_comm.is_empty() {
            // there must be one dummy1 commitment
            let dummy_comm: Vec<&Commitment> = self
                .commitments
                .iter()
                .filter(|c| c.typ == CommitmentType::dummy1)
                .collect();
            if dummy_comm.is_empty() {
                return Err(Error::VerificationError);
            }
            if dummy_comm.len() != 1 {
                return Err(Error::VerificationError);
            }
            dummy_comm[0].comm
        } else {
            // collect first halves of all authdecode commitments,
            // see `[CommitmentType::authdecode]`
            // authdecode_comm.iter().map(|c| c.comm[0..16]).flatten();
            [0u8; 32]
        };

        // TODO: handle a case when there are no commitments at all

        // hash all commitments from authdecode Step8 followed by all other commitments
        let mut second_hash_preimage: Vec<u8> = Vec::new();
        let authdecode_step8 = authdecode_comm
            .iter()
            .map(|c| c.comm[16..32])
            .flatten()
            .collect::<Vec<u8>>();

        // also append all other commitments.
        let other_comm: Vec<u8> = self
            .commitments
            .iter()
            .filter(|c| c.typ != CommitmentType::authdecode)
            .map(|c| c.comm)
            .flatten()
            .collect();

        second_hash_preimage.append(&mut authdecode_step8);
        second_hash_preimage.append(&mut other_comm);

        // TODO hash 1 preimage and 2nd preimage, concat them and assert equality with
        // self.aggregated_commitment
        Ok(())
    }

    // Verify each commitment against its opening
    fn verify_each_commitment(&self) -> Result<(), Error> {
        // TODO break up commitments and openings into pairs, then for each pair:
        let comm = self.commitments[0];
        let open = self.commitment_openings[0];
        comm.verify(open)?;

        Ok(())
    }
}

#[derive(Clone)]
struct Pubkey {
    typ: Curve,
    pubkey: Vec<u8>,
}

// signature for the notarization doc
#[derive(Clone)]
pub struct Signature {
    pub typ: Curve,
    pub signature: Vec<u8>,
}
