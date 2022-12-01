use super::{Commitment, Error};
use crate::main_doc::SignedData;
use crate::public_data::{PublicData, PublicDataOneRound};
use rand::Rng;
use rand_chacha::ChaCha12Rng;
use rand_core::{RngCore, SeedableRng};

// Bytesize of one request followed by one response (this consitutes one round of notarization).
// There may be single-round or multi-round notarizations.

#[derive(Default, Clone)]
pub struct RoundSize {
    pub request: u32,
    pub response: u32,
}

#[derive(Clone, Default)]
// public and private data for one round for one direction (either request or response)
// all fields are optional since a round may contain only public data or only
// private data
// we may have private data in either request or response or both
struct PrivateDataOneRound {
    request: Option<Vec<CommitmentIdWithRanges>>,
    response: Option<Vec<CommitmentIdWithRanges>>,
}

/// all private data from all rounds of the notarization session
type PrivateData = Vec<PrivateDataOneRound>;

/// both public and private data from ONE round of
/// the notarization session. A round may have only public data
/// or only private data, or both.
struct DataOneRound {
    public: Option<PublicDataOneRound>,
    private: Option<PrivateDataOneRound>,
}

/// both public and private data from all rounds of
/// the notarization session
type Data = Vec<DataOneRound>;

#[derive(Clone)]
enum SeedType {
    chacha12,
    chacha20,
    fixed_key_aes,
}

#[derive(Clone)]
struct Seed {
    typ: SeedType,
    value: Vec<u8>,
}

#[derive(Clone)]
/// All the PRG seeds from which to generate Notary's circuits' input labels
pub struct LabelSeeds {
    // the seeds are arranged in this order:
    // - the seeds covering all the requests ascendingly
    // - the seeds covering all the responses ascendingly
    seeds: Vec<Seed>,
    // how many u128 values (delta + labels) to expand each seed into
    expand_into_count: u32,
}

#[derive(Clone)]
enum Direction {
    Request,
    Response,
}

#[derive(Clone)]
/// exclusive range [start, end)
pub struct Range {
    pub start: u32,
    pub end: u32,
}

#[derive(Clone)]
/// id of the private data commitment and the range bounds of the private data
/// Range bounds must be relative to the round of notarization
/// The commitment is allowed to cover only one request or one response
struct CommitmentIdWithRanges {
    range: Vec<Range>,
    id: usize,
}

#[derive(Clone)]
pub struct PrivateDataCommitment {
    // the unique id of this commitment
    id: usize,
    /// Commitment to the private data from a single notarization round
    commitment: Commitment,
    // ranges of absolute position in which decoded labels' values are located in the TLS transcript
    // Ranges must not overlap and must be in an ascending order
    direction: Direction,
    label_ranges: Vec<Range>,
}

impl PrivateDataCommitment {
    pub fn serialize(&self) -> Vec<u8> {
        vec![0u8; 100]
    }
}

enum ZKProofType {
    // the property of the private data that is proved in zk
    range_proof,
    absence_of_character_in_string,
    membership_in_a_set,
}

enum ZKProofBackend {
    halo2,
    snarkjs,
    plonky2,
}

struct ZKProof {
    typ: ZKProofType,
    backend: ZKProofBackend,
    proof: Vec<u8>,
    // tbd proof type-dependent parameters, public inputs, etc
    data: Vec<u8>,
}

// DataDoc contains the info to verify public commitments and zkproofs about private
// data.
pub struct DataDoc {
    version: u8,
    pub public_data: PublicData,
    zkproofs: Vec<ZKProof>,
}

impl DataDoc {
    // pub fn new() -> Self {
    //     //todo
    // }

    /// verifies the data in the DataDoc
    pub fn verify(&self, signed_data: SignedData) -> Result<bool, Error> {
        // check public data of each round
        for (i, pd) in self.public_data.iter().enumerate() {
            if !pd.check(&signed_data.roundSizes[i]) {
                return Err(Error::VerificationError);
            }
        }

        // we don't check ranges of private data because we trust the Notary to provide
        // properly-formed private ranges

        // expand the seed, select active labels for public data in ranges, add salt,
        // check commitment (2)
        self.check_public_commitments(
            &signed_data.labelSeeds,
            &self.public_data,
            &signed_data.public_commitments,
            &signed_data.roundSizes,
        )?;

        self.verify_zk_proofs(&self.zkproofs, &signed_data.private_commitments)?;

        // TODO perform some sanity checks:
        // - do we allow the public data to overlap with the private data?
        // - some other corner cases?

        Ok(true)
    }

    // expand the seed
    // select active labels for public data in ranges, add salt, check commitment (2)
    fn check_public_commitments(
        &self,
        seeds: &LabelSeeds,
        data: &PublicData,
        commitment: &Vec<Option<Commitment>>,
        sizes: &Vec<RoundSize>,
    ) -> Result<bool, Error> {
        // ---------------------- first expand all the labels for the requests: ----------------------

        // calculate total amount of bits in all requests
        let req_total: u32 = sizes.iter().map(|sz| sz.request).sum();

        // TODO: block size must be specified in the doc by the Notary
        let block_size = 16;
        let blocks_total = req_total / block_size;

        // the plaintext input labels are not the only input labels of the circuit.
        // we will first expand all input labels but will pick only the input labels
        // corresponding to the plaintext.
        // TODO this number must be taken from the circuit's description
        let labels_per_circuit = 256;

        // How many labels corresponding to the plaintext we need. Note that one circuit
        // encrypts one block of data.
        let total_labels_needed = labels_per_circuit * blocks_total;

        let mut labels_so_far: Vec<u128> = Vec::with_capacity(total_labels_needed as usize);

        // tracks how many seeds have been already processed
        let mut seeds_so_far = 0u8;

        for seed in seeds.seeds {
            let rng = ChaCha12Rng::from_seed(seed.value.try_into().unwrap());
            let values = (0..seeds.expand_into_count)
                .map(|_| rng.gen())
                .collect::<Vec<u128>>();
            // TODO drop the first value (the delta) and also all the labels which
            // are not the plaintext labels so that `values` contains only the plaintext labels
            labels_so_far.extend(values);
            seeds_so_far += 1;
            if labels_so_far.len() >= (total_labels_needed as usize) {
                break;
            }
        }

        // TODO not finished because we need to agree exactly how the Notary generates
        // the seeds
        Ok(true)
    }

    fn verify_zk_proofs(
        &self,
        proofs: &Vec<ZKProof>,
        commitments: &Vec<Option<PrivateDataCommitment>>,
    ) -> Result<bool, Error> {
        // TODO
        Ok(true)
    }
}
