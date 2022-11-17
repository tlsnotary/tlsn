use super::data_doc::{LabelSeeds, PrivateDataCommitment, RoundSize};
use super::verify_signature;
use super::webpki_utils;
/// The main notarization document attesting to the authenticity of a TLS
/// session.
/// The data being attested to is not included here but will be part of the
/// VerifierDoc
use super::{Curve, Error, Pubkey};
use crate::Commitment;
// an x509 cert in DER format
pub type CertDER = Vec<u8>;

pub struct MainDoc {
    version: u8,
    signed: SignedData,
    signature: Option<Signature>,
    committedTLS: CommittedTLS,
}

impl MainDoc {
    // pub fn new() -> Self {
    //     //todo
    // }

    /// verifies the MainDoc. Checks that `hostname` is present in the leaf certificate.
    /// trusted notary's pubkey. If the doc has a signature, the pubkey is expected to
    /// verify the sig.
    pub fn verify(&self, hostname: String, pubkey: Option<Pubkey>) -> Result<bool, Error> {
        if self.signature.is_some() {
            if pubkey.is_none() {
                return Err(Error::VerificationError);
            } else {
                // check Notary's signature on signed data
                self.verify_doc_signature(
                    &pubkey.unwrap(),
                    &self.signature.as_ref().unwrap(),
                    &self.signed,
                )?;
            }
        }

        // check TLS certificate chain against local root certs. Some certs in the chain may
        // have expired at the time of this verification. We check their validity at the time
        // of notarization

        if !webpki_utils::check_tls_cert_chain(&self.committedTLS.tls_cert_chain, self.signed.time)
        {
            return Err(Error::VerificationError);
        }

        let leaf_cert = webpki_utils::extract_leaf_cert(&self.committedTLS.tls_cert_chain);

        if !self.check_tls_commitment(&self.committedTLS, &self.signed.commitment_to_TLS) {
            return Err(Error::VerificationError);
        }

        //check that TLS key exchange parameters were signed by the leaf cert
        if !webpki_utils::check_sig_ke_params(
            &leaf_cert,
            &self.committedTLS.sig_ke_params,
            &self.signed.ephemeralECPubkey,
            &self.committedTLS.client_random,
            &self.committedTLS.server_random,
        ) {
            return Err(Error::VerificationError);
        }

        if !webpki_utils::check_hostname_present_in_cert(&leaf_cert, hostname) {
            return Err(Error::VerificationError);
        }

        Ok(true)
    }

    // returns fields needed to perform verification of the DataDoc
    pub fn fields_for_data_doc_verification(
        &self,
    ) -> (
        Vec<RoundSize>,
        LabelSeeds,
        Commitment,
        Vec<PrivateDataCommitment>,
    ) {
        (
            self.signed.roundSizes.clone(),
            self.signed.labelSeeds.clone(),
            self.signed.commitment_to_active_labels.clone(),
            self.signed.commitments_to_private_data.clone(),
        )
    }

    // verify Notary's sig on the notarization doc
    fn verify_doc_signature(
        &self,
        pubkey: &Pubkey,
        sig: &Signature,
        to_be_signed: &SignedData,
    ) -> Result<bool, Error> {
        let tbs_serialized = to_be_signed.serialize();
        if pubkey.typ != sig.typ {
            return Err(Error::VerificationError);
        }
        let result = match sig.typ {
            Curve::secp256k1 => {
                verify_signature::verify_sig_p256(&tbs_serialized, &pubkey.pubkey, &sig.signature)
            }
            _ => false,
        };
        if !result {
            return Err(Error::VerificationError);
        } else {
            Ok(true)
        }
    }

    // check the commitment (1) to misc TLS data
    fn check_tls_commitment(&self, committedTLS: &CommittedTLS, commitment: &Commitment) -> bool {
        commitment.check(committedTLS.serialize())
    }
}

#[derive(Clone)]
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
    pub fn serialize(&self) -> Vec<u8> {
        vec![0u8; 100]
    }

    // convert into a tbd format which can be stored on disk
    pub fn to_intermediate_format(&self) {}
}

// Misc TLS data which the User committed to before the User and the Notary engaged in 2PC
// to compute the TLS session keys
//
// The User should not reveal `tls_cert_chain` because the Notary would learn the webserver name
// from it. The User also should not reveal `signature_over_ephemeral_key` to the Notary, because
// for ECDSA sigs it is possible to derive the pubkey from the sig and then use that pubkey to find out
// the identity of the webserver.
//
// Note that there is no need to include the ephemeral key because it will be signed explicitely
// by the Notary.
struct CommittedTLS {
    tls_cert_chain: Vec<CertDER>,
    sig_ke_params: SignatureKeyExchangeParams,
    client_random: Vec<u8>,
    server_random: Vec<u8>,
}

impl CommittedTLS {
    pub fn new(
        tls_cert_chain: Vec<CertDER>,
        sig_ke_params: SignatureKeyExchangeParams,
        client_random: Vec<u8>,
        server_random: Vec<u8>,
    ) -> Self {
        Self {
            tls_cert_chain,
            sig_ke_params,
            client_random,
            server_random,
        }
    }

    // return a serialized structure which can be hashed
    pub fn serialize(&self) -> Vec<u8> {
        vec![0u8; 100]
    }
}

#[derive(Clone)]

pub enum EphemeralECPubkeyType {
    p256,
    ed25519,
}

#[derive(Clone)]
pub struct EphemeralECPubkey {
    pub typ: EphemeralECPubkeyType,
    pub pubkey: Vec<u8>,
}

// signature for the notarization doc
struct Signature {
    typ: Curve,
    signature: Vec<u8>,
}

// Various key exchange params signature algorithms supported by TLS 1.2 spec
pub enum SigKEParamsType {
    rsa_pkcs1_sha256,
}

// signature over the TLS key exchange params
pub struct SignatureKeyExchangeParams {
    pub typ: SigKEParamsType,
    pub sig: Vec<u8>,
}
