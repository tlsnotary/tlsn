enum EphemeralECPubkeyType {
    p256,
    ed25519,
}

struct EphemeralECPubkey {
    typ: EphemeralECPubkeyType,
    pubkey: Vec<u8>,
}

enum CommitmentType {
    sha256,
    blake2f,
    poseidon,
    mimc,
}

struct Commitment {
    typ: CommitmentType,
    commitment: Vec<u8>,
}

enum SeedType {
    chacha12,
    chacha20,
    fixed_key_aes,
}

struct Seed {
    typ: SeedType,
    seed: Vec<u8>,
}

/// All the PRG seeds from which to generate Notary's circuits' input labels
struct LabelSeeds {
    seeds: Vec<Seed>,
    // how many labels to expand each seed into
    expand_into_count: u32,
}

/// The bytesize of one round: i.e. one request followed by one response
struct RoundSize(u32, u32);

enum Direction {
    Request,
    Response,
}

/// exclusive range (direction, [start, end) )
struct Range(Direction, u32, u32);

/// Commitment to the private data
struct PrivateDataCommitment {
    commitment: Commitment,
    // ranges of absolute position in which decoded labels are located in the TLS transcript
    label_ranges: Vec<Range>,
}

struct SignedData {
    time: u64,
    ephemeralECPubkey: EphemeralECPubkey,
    roundSizes: Vec<RoundSize>,
    commitment_to_TLS: Commitment,
    labelSeeds: LabelSeeds,
    commitment_to_active_labels: Commitment,
    // this is the commitments from the authdecode protocol
    commitments_to_private_data: Vec<PrivateDataCommitment>,
}

impl SignedData {
    pub fn new(
        time: u64,
        ephemeralECPubkey: EphemeralECPubkey,
        roundSizes: Vec<RoundSize>,
        commitment_to_TLS: Commitment,
        labelSeeds: LabelSeeds,
        commitment_to_active_labels: Commitment,
        commitments_to_private_data: Vec<PrivateDataCommitment>,
    ) -> Self {
        Self {
            time,
            ephemeralECPubkey,
            roundSizes,
            commitment_to_TLS,
            labelSeeds,
            commitment_to_active_labels,
            commitments_to_private_data,
        }
    }

    // return a serialized struct which can be signed or verified
    pub fn serialize() {}

    // convert into a tbd format which can be stored on disk
    pub fn to_intermediate_format() {}
}

enum Curve {
    // different curves
    secp256k1,
    p256,
    bn254,
    bls12381,
    pallas,
}

struct Signature {
    typ: Curve,
    signature: Vec<u8>,
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

// The notarization document
struct Doc {
    version: u8,
    signed: SignedData,
    signature: Option<Signature>,

    // additional data
    tls_cert_chain: Vec<u8>,
    signature_over_ephemeral_key: Vec<u8>,
    client_random: Vec<u8>,
    server_random: Vec<u8>,

    // per-verifier data
    public_data: PublicData,
    // salt for public data commitment
    salt: Salt,
    zkproofs: Vec<ZKProof>,
}

struct Pubkey {
    typ: Curve,
    pubkey: Vec<u8>,
}

// one request followed by one response constitute one round. There may be a
// single-round or a multi-round notarizations.
#[derive(Default)]
struct Round {
    request: Vec<u8>,
    response: Vec<u8>,
}

struct Verifier {
    // notarization doc which needs to be verified
    doc: Doc,
    // trusted notary's pubkey. If this Verifier is also the Notary then no pubkey needs
    // to be provided, the signature on the `SignedData` will not be checked.
    trusted_pubkey: Option<Pubkey>,
}

enum Error {
    VerificationError,
}

impl Verifier {
    pub fn new(doc: Doc, trusted_pubkey: Option<Pubkey>) -> Self {
        Self {
            doc,
            trusted_pubkey,
        }
    }

    pub fn verify(&self) -> Result<bool, Error> {
        if self.doc.signature.is_some() {
            if self.trusted_pubkey.is_none() {
                return Err(Error::VerificationError);
            } else {
                // check Notary's signature on signed data
                self.check_doc_signature(
                    &self.trusted_pubkey.as_ref().unwrap(),
                    &self.doc.signature.as_ref().unwrap(),
                    &self.doc.signed,
                )?;
            }
        }

        // check TLS certificate chain against local root certs. Some certs in the chain may
        // have expired at the time of this verification. We check their validity at the time
        // of notarization
        self.check_tls_cert_chain(&self.doc.tls_cert_chain, self.doc.signed.time)?;

        let leaf_cert = self.extract_leaf_cert(&self.doc.tls_cert_chain);

        self.check_tls_commitment(
            &self.doc.tls_cert_chain,
            &self.doc.signature_over_ephemeral_key,
            &self.doc.client_random,
            &self.doc.server_random,
            &self.doc.signed.commitment_to_TLS,
        )?;

        //check that ephem. EC pubkey + randoms were signed by the leaf cert
        self.check_ephemeral_ec_signature(
            &leaf_cert,
            &self.doc.signature_over_ephemeral_key,
            &self.doc.signature_over_ephemeral_key,
            &self.doc.client_random,
            &self.doc.server_random,
        )?;

        self.check_public_data(&self.doc.public_data, &self.doc.signed.roundSizes)?;

        let rounds = self.build_public_data(&self.doc.public_data);

        let names = self.extract_cert_common_name(&leaf_cert);

        // check that the common name from the leaf certificate matches the "Host" header
        // of the request (prevent the domain fronting attack)
        self.check_host_header(names, rounds)?;

        // expand the seed
        // select active labels for public data in ranges, add salt, check commitment (2)
        self.check_label_commitment(
            &self.doc.signed.labelSeeds,
            &self.doc.public_data,
            &self.doc.salt,
            &self.doc.signed.commitment_to_active_labels,
        )?;

        self.verify_zk_proofs(
            &self.doc.zkproofs,
            &self.doc.signed.commitments_to_private_data,
        )?;

        // TODO perform some sanity checks:
        // - do we allow the public data to overlap with the private data?
        // - some other corner cases?

        Ok(true)
    }

    fn check_doc_signature(
        &self,
        pubkey: &Pubkey,
        sig: &Signature,
        to_be_signed: &SignedData,
    ) -> Result<bool, Error> {
        Ok(true)
    }

    // check that cert chain was valid at the time when notarization was performed
    fn check_tls_cert_chain(&self, chain: &Vec<u8>, time: u64) -> Result<bool, Error> {
        Ok(true)
    }

    // return the leaf certificate from the chain (the last one)
    fn extract_leaf_cert(&self, chain: &Vec<u8>) -> Vec<u8> {
        vec![0u8; 100]
    }

    // check the commitment (1) to misc TLS data
    fn check_tls_commitment(
        &self,
        cert_chain: &Vec<u8>,
        ephem_ec_signature: &Vec<u8>,
        client_random: &Vec<u8>,
        server_random: &Vec<u8>,
        commitment: &Commitment,
    ) -> Result<bool, Error> {
        Ok(true)
    }

    fn check_ephemeral_ec_signature(
        &self,
        cert: &Vec<u8>,
        ephem_ec_sig: &Vec<u8>,
        ephem_ec: &Vec<u8>,
        client_random: &Vec<u8>,
        server_random: &Vec<u8>,
    ) -> Result<bool, Error> {
        Ok(true)
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

    // Extract the cert's common name (and, if present, alt names)
    fn extract_cert_common_name(&self, cert: &Vec<u8>) -> Vec<String> {
        vec!["example.com".to_string(), "example2.com".to_string()]
    }

    // check that the common name from the leaf certificate matches the "Host" header
    // of the request (prevent domain fronting attack)
    fn check_host_header(&self, names: Vec<String>, rounds: Vec<Round>) -> Result<bool, Error> {
        Ok(true)
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
