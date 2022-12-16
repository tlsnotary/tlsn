use super::Error;

// A User's commitment to a portion of the TLS transcript
#[derive(Clone)]
pub struct Commitment {
    id: usize,
    pub typ: CommitmentType,
    direction: Direction,
    // the actual commitment
    pub comm: [u8; 32],
    // ranges of absolute offsets in the TLS transcript. The committed data
    // is located in those ranges.
    ranges: Vec<Range>,
}

impl Commitment {
    pub fn new(
        id: usize,
        typ: CommitmentType,
        direction: Direction,
        comm: [u8; 32],
        ranges: Vec<Range>,
    ) -> Self {
        Self {
            id,
            typ,
            direction,
            comm,
            ranges,
        }
    }

    // check this commitment against the opening
    pub fn verify(&self, opening: CommitmentOpening) -> Result<(), Error> {
        if self.typ == CommitmentType::labels_blake3 {
            // TODO how do we pass here the PRG seed from which to expand labels?

            // expand the PRG seed, select only the labels belonging to the ranges
            // hash the labels, check the commitment
        } else if self.typ == CommitmentType::authdecode {
            // TODO how do we pass here the PRG seed from which to expand labels?

            // expand the PRG seed, locally break label correlation
            // compute deltas and zero_sum (see authdecode diagram)
            // verify the zkproof in opening.zkproofs
        } else if self.typ == CommitmentType::poseidon {
            // verify the zk proof against this poseidon commitment
        }

        Ok(())
    }
}

#[derive(Clone, PartialEq)]
pub enum CommitmentType {
    // a sha256 hash of the wire labels corresponding to the bits being committed to
    labels_sha256,
    // a blake3 hash of the wire labels corresponding to the bits being committed to
    labels_blake3,
    // A concatenation of blake3 commitment from Step 3 of the authdecode diagram followed by
    // a blake3 commitment from Step 8 of the authdecode diagram
    // https://github.com/tlsnotary/tlsn/blob/authdecode/authdecode/authdecode_diagram.pdf
    authdecode,
    // a random value which the User sends when there are no authdecode commitments. This is
    // done for User privacy to keep the Notary from knowing that there were no authdecode
    // commitments
    dummy1,

    // a random value which the User sends when there are no commitments at all. This is
    // done for User privacy to keep the Notary from knowing that there are no commitments.
    dummy2,

    // The 2 types below are used in a mode when the Notary already verified the zk proofs
    // in the authdecode protocol.
    // This mode has downsides for User privacy, since the Notary will learn which parts of
    // the TLS transcript the User wants to make zk-friendly.
    // The benefit of using this mode is that the Verifier doesn't need to verify zk-proofs
    // from the authdecode protocol. Instead, the Notary verifies them once and signs the hash
    // of the plaintext.

    // a poseidon hash of the plaintext committed to
    poseidon,
    // a mimc hash of the plaintext committed to
    mimc,
}

// Commitment opening contains either the committed value or a zk proof
// about some property of that value
#[derive(Clone)]
pub struct CommitmentOpening {
    /// the id of the [Commitment] corresponding to this opening
    id: usize,
    // the actual opening of the commitment. Optional because a zk proof
    // about some property of the opening can be provided instead
    opening: Option<Vec<u8>>,
    // all our commitments are salted
    salt: Vec<u8>,
    // a zk proof about some property of the opening. Optional because the actual opening
    // can be revealed instead. There can be potentially multiple proofs about multiple
    // properties of one opening.
    zkproofs: Option<Vec<ZKProof>>,
}

#[derive(Clone)]
// A TLS transcript consists of a stream of bytes which were sent to the server (Request)
// and a stream of bytes which were received from the server (Response). The User creates
// separate commitments to bytes in each direction.
pub enum Direction {
    Request,
    Response,
}

#[derive(Clone)]
/// exclusive range [start, end)
pub struct Range {
    pub start: usize,
    pub end: usize,
}

#[derive(Clone)]
enum ZKProofType {
    // the property of the private data that is proved in zk
    range_proof,
    absence_of_character_in_string,
    membership_in_a_set,
}

#[derive(Clone)]
enum ZKProofBackend {
    halo2,
    snarkjs,
    plonky2,
}

#[derive(Clone)]
struct ZKProof {
    typ: ZKProofType,
    backend: ZKProofBackend,
    proof: Vec<u8>,
    // tbd proof type-dependent parameters, public inputs, etc
    data: Vec<u8>,
}
