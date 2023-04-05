pub mod commitment;
pub mod encoder;
pub mod error;
pub mod handshake_data;
pub mod handshake_summary;
pub(crate) mod inclusion_proof;
pub mod merkle;
pub mod notarized_session;
pub mod pubkey;
pub mod session_artifacts;
pub mod session_data;
pub mod session_header;
pub mod session_proof;
pub mod signature;
pub mod signer;
pub mod substrings_commitment;
pub mod substrings_opening;
pub mod substrings_proof;
pub mod transcript;
mod utils;
mod webpki_utils;

pub use session_data::SessionData;
pub use session_header::SessionHeader;

pub type HashCommitment = [u8; 32];

#[cfg(test)]
pub mod test {

    use crate::{
        notarized_session::NotarizedSession,
        pubkey::{KeyType, PubKey},
        session_artifacts::SessionArtifacts,
        session_header::{LabelSeed, SessionHeader, SessionHeaderMsg},
        session_proof::SessionProof,
        signer::Signer,
        HashCommitment, SessionData,
    };
    use p256::ecdsa::{signature::DigestSigner, SigningKey, VerifyingKey};
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    #[test]
    fn test() {
        // At the end of the session the User holds these artifacts:
        // time when TLS handshake began
        let time = 0u64;
        // merkle root of all User's commitments
        let merkle_root = [0u8; 32];
        // label seed revealed by the Notary at the end of the label commitment protocol
        let label_seed: LabelSeed = LabelSeed::default();
        // server ephemeral key
        let ephem_key: PubKey = PubKey::default();
        // handshake commitment
        let handshake_commitment = HashCommitment::default();
        let artifacts = SessionArtifacts::new(
            time,
            merkle_root,
            label_seed,
            ephem_key,
            handshake_commitment,
        );

        // Notary's receives the raw signing key from some outer context
        let signer = Signer::new(KeyType::P256, &[1; 32]).unwrap();
        let pubkey = signer.verifying_key();

        // Notary creates the header with SessionHeader::new() (using ::default() here for simplicity)
        let header = SessionHeader::default();

        let signature = header.sign(&signer).unwrap();
        // Notary creates a msg and sends it to User
        // (if the Notary is the Verifier then no signature is required and None is passed)
        let msg = SessionHeaderMsg::new(&header, Some(signature));

        // User verifies the header and stores it with the signature in NotarizedSession
        let header = SessionHeader::from_msg(&msg, Some(&pubkey)).unwrap();
        header.check_artifacts(&artifacts).unwrap();
        let signature = msg.signature();

        let data = SessionData::default();
        let session = NotarizedSession::new(1, header, signature, data);

        // User converts NotarizedSession into SessionProof and SubstringsProof and sends them to the Verifier
        let session_proof: SessionProof = (&session).into();
        let substrings_proof = session.generate_substring_proof([1, 2].to_vec()).unwrap();

        // The Verifier does:
        let SessionProof {
            header,
            handshake_data,
        } = session_proof;

        // (if the Notary is the Verifier then no pubkey is required and None is passed)
        let header = SessionHeader::from_msg(&header, Some(&pubkey)).unwrap();

        handshake_data.verify(&header, "tlsnotary.org").unwrap();

        let transcript_slices = substrings_proof.verify(&header).unwrap();
    }
}
