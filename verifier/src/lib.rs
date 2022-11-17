mod data_doc;
mod main_doc;
mod verify_signature;
mod webpki_utils;

use crate::data_doc::DataDoc;
use crate::main_doc::MainDoc;

#[derive(Clone)]
enum CommitmentType {
    sha256,
    blake2f,
    poseidon,
    mimc,
}

#[derive(Clone)]
struct Commitment {
    typ: CommitmentType,
    commitment: Vec<u8>,
}

impl Commitment {
    pub fn new(typ: CommitmentType, data_committed_to: Vec<u8>) -> Self {
        // TODO match various commitment types and hash accordingly
        let commitment = vec![0u8; 100];
        Self { typ, commitment }
    }

    // check if this commitment was created from `data_committed_to`
    pub fn check(&self, data_committed_to: Vec<u8>) -> bool {
        // TODO match various commitment types and hash accordingly
        let commitment = vec![0u8; 100];
        if self.commitment == commitment {
            return true;
        } else {
            return false;
        }
    }
}

/// The actual document which the verifier will receive
struct VerifierDoc {
    version: u8,
    main_doc: MainDoc,
    data_doc: DataDoc,
}

struct Verifier {
    // notarization doc which needs to be verified
    doc: VerifierDoc,
    // trusted notary's pubkey. If this Verifier is also the Notary then no pubkey needs
    // to be provided, the signature on the `SignedData` will not be checked.
    trusted_pubkey: Option<Pubkey>,
}

#[derive(Debug)]
enum Error {
    VerificationError,
}

impl Verifier {
    pub fn new(doc: VerifierDoc, trusted_pubkey: Option<Pubkey>) -> Self {
        Self {
            doc,
            trusted_pubkey,
        }
    }

    pub fn verify(&self) -> Result<bool, Error> {
        // the signed portion of the main doc contains commitments and other data
        // needed to verify the data doc
        let (rs, ls, cal, cpd) = self.doc.main_doc.fields_for_data_doc_verification();
        let res = self.doc.data_doc.verify(&rs, &ls, &cal, &cpd);
        if res.is_err() {
            return Err(Error::VerificationError);
        }
        let hostname = res.unwrap();

        self.doc
            .main_doc
            .verify(hostname, self.trusted_pubkey.clone())
    }
}

#[derive(Clone)]
struct Pubkey {
    typ: Curve,
    pubkey: Vec<u8>,
}

#[derive(PartialEq, Clone)]
enum Curve {
    // different curves
    secp256k1,
    p256,
    bn254,
    bls12381,
    pallas,
}
