use super::{Commitment, Error};
pub struct DataDoc {
    version: u8,
    public_data: PublicData,
    // salt for public data commitment
    salt: Salt,
    zkproofs: Vec<ZKProof>,
}

impl DataDoc {
    // pub fn new() -> Self {
    //     //todo
    // }

    /// verifies the data in the DataDoc. Returns the value of the "Host" header
    /// The host must be a DNS name for which the leaf certificate was issued
    pub fn verify(
        &self,
        roundSizes: &Vec<RoundSize>,
        labelSeeds: &LabelSeeds,
        commitment_to_active_labels: &Commitment,
        commitments_to_private_data: &Vec<PrivateDataCommitment>,
    ) -> Result<String, Error> {
        self.check_public_data(&self.public_data, roundSizes)?;

        let rounds = self.build_public_data(&self.public_data);

        let hostname = self.check_host_header(rounds)?;

        // expand the seed
        // select active labels for public data in ranges, add salt, check commitment (2)
        self.check_label_commitment(
            labelSeeds,
            &self.public_data,
            &self.salt,
            commitment_to_active_labels,
        )?;

        self.verify_zk_proofs(&self.zkproofs, commitments_to_private_data)?;

        // TODO perform some sanity checks:
        // - do we allow the public data to overlap with the private data?
        // - some other corner cases?

        Ok(hostname)
    }

    // checks that no public ranges overlap
    // checks that amount of public data is not larger than request/response total size
    fn check_public_data(&self, data: &PublicData, sizes: &Vec<RoundSize>) -> Result<bool, Error> {
        Ok(true)
    }

    // expand public data into 2 sparse bytevectors : one for all the requests and one
    // for all the responses. The gaps in the sparse array correspond to the data which was
    // not made public.
    // Split them up into individual rounds
    fn build_public_data(&self, data: &PublicData) -> Vec<Round> {
        vec![Round::default()]
    }

    // check that the request in each round contains only one "Host" header and
    // that all Host headers of all rounds are the same
    fn check_host_header(&self, rounds: Vec<Round>) -> Result<String, Error> {
        Ok("hostname".to_string())
    }

    // expand the seed
    // select active labels for public data in ranges, add salt, check commitment (2)
    fn check_label_commitment(
        &self,
        seeds: &LabelSeeds,
        data: &PublicData,
        salt: &Salt,
        commitment: &Commitment,
    ) -> Result<bool, Error> {
        Ok(true)
    }

    fn verify_zk_proofs(
        &self,
        proofs: &Vec<ZKProof>,
        commitments: &Vec<PrivateDataCommitment>,
    ) -> Result<bool, Error> {
        Ok(true)
    }
}

// one request followed by one response constitute one round. There may be a
// single-round or a multi-round notarizations.
#[derive(Default)]
struct Round {
    request: Vec<u8>,
    response: Vec<u8>,
}

#[derive(Clone)]
enum SeedType {
    chacha12,
    chacha20,
    fixed_key_aes,
}

#[derive(Clone)]
struct Seed {
    typ: SeedType,
    seed: Vec<u8>,
}

#[derive(Clone)]
/// All the PRG seeds from which to generate Notary's circuits' input labels
pub struct LabelSeeds {
    seeds: Vec<Seed>,
    // how many labels to expand each seed into
    expand_into_count: u32,
}

#[derive(Clone)]
/// The bytesize of one round: i.e. one request followed by one response
pub struct RoundSize(u32, u32);

#[derive(Clone)]
enum Direction {
    Request,
    Response,
}

#[derive(Clone)]
/// exclusive range (direction, [start, end) )
struct Range(Direction, u32, u32);

#[derive(Clone)]
/// Commitment to the private data
pub struct PrivateDataCommitment {
    commitment: Commitment,
    // ranges of absolute position in which decoded labels are located in the TLS transcript
    label_ranges: Vec<Range>,
}

// salt for the public data commitment
type Salt = [u8; 128];

struct PublicData {
    data: Vec<u8>,
    // ranges in which the data is located
    ranges: Vec<Range>,
}

enum ZKProofType {
    // the property of the private data that is proved in zk
    range_proof,
    absence_of_character_in_string,
    membership_in_a_set,
}

struct ZKProof {
    typ: ZKProofType,
    proof: Vec<u8>,
    // proof type-dependent parameters, public inputs, etc
    data: Vec<u8>,
}
