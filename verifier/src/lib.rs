mod data_doc;
mod main_doc;
mod public_data;
mod verify_signature;
mod webpki_utils;

use public_data::PublicData;

use crate::data_doc::DataDoc;
use crate::main_doc::MainDoc;

/// The actual document which the verifier will receive
struct VerifierDoc {
    version: u8,
    main_doc: MainDoc,
    data_doc: DataDoc,
}

#[derive(Debug)]
enum Error {
    VerificationError,
}

/// Verifies the correctness of the  HTTP 1.0/1.1 notarization session
struct HTTP1Verifier {
    verifier_core: VerifierCore,
}

impl HTTP1Verifier {
    pub fn new(doc: VerifierDoc, trusted_pubkey: Option<Pubkey>) -> Self {
        Self {
            verifier_core: VerifierCore::new(doc, trusted_pubkey),
        }
    }

    /// verifies that this session came from the server with the dns_name
    /// and there was no domain fronting
    pub fn verify(&self, dns_name: String) -> Result<bool, Error> {
        if self.verifier_core.verify(dns_name).is_err() {
            return Err(Error::VerificationError);
        }
        if self
            .domain_fronting_attack_check(dns_name, self.verifier_core.doc.data_doc.public_data)
            .is_err()
        {
            return Err(Error::VerificationError);
        }

        Ok(true)
    }

    /// Each request must contain a single Host header which matches the dns_name
    fn domain_fronting_attack_check(
        &self,
        dns_name: String,
        pub_data: PublicData,
    ) -> Result<bool, Error> {
        for round_data in pub_data {
            // search round_data.request ranges one-by-one until the '/r/n/r/n' delimiter
            // is found. (This delimiter separates the headers from the payload). Split off
            // the headers ranges. Make sure there is no zero bytes in the headers ranges.
            // Fill the gaps in headers ranges with zero bytes. Flatten all headers ranges
            // into one bytestring.

            // split the bytestring by '/r/n' (the separator between individual headers)
            // into individual headers. Make sure there is only one Host header which matches
            // `dns_name`.

            // No substring in the headers can be hidden (i.e. neither public nor private).
            // If it is private, it must have a corresponding zkp that the substring does not
            // contain any '/r/n'. This ensures that an extra Host header is not hidden inside
            // the private data.
        }

        Ok(true)
    }
}

struct VerifierCore {
    /// notarization doc which needs to be verified
    doc: VerifierDoc,
    /// trusted notary's pubkey. If this Verifier is also the Notary then no pubkey needs
    /// to be provided, the signature on the [crate::main_doc::MainDoc] will not be checked.
    trusted_pubkey: Option<Pubkey>,
}

/// verifies the core aspects of the notarization session: the Notary signature, the TLS
/// authenticity and the correctness of public data and zk proofs.
///
/// Other checks like checking for domain fronting attack will be done by a higher
/// level verifier like e.g. HTTP1Verifier
impl VerifierCore {
    pub fn new(doc: VerifierDoc, trusted_pubkey: Option<Pubkey>) -> Self {
        Self {
            doc,
            trusted_pubkey,
        }
    }

    /// verifies that this session came from the server with the dns_name
    ///
    /// Note that the checks below are not sufficient to establish data provenance.
    /// There also must be a check done on a higher level against the domain fronting
    /// attack.
    pub fn verify(&self, dns_name: String) -> Result<bool, Error> {
        // check the TLS session authenticity
        self.doc
            .main_doc
            .verify(dns_name, self.trusted_pubkey.clone());

        // the signed_data contains commitments and also other data needed to
        // verify the DataDoc
        let signed_data = self.doc.main_doc.signed_data();

        // verify the commitments to public data and zk proofs about private data
        if self.doc.data_doc.verify(signed_data).is_err() {
            return Err(Error::VerificationError);
        }

        Ok(true)
    }
}

#[derive(Clone)]
pub enum CommitmentType {
    sha256,
    blake2f,
    poseidon,
    mimc,
}

#[derive(Clone)]
pub struct Commitment {
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
