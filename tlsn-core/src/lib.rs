pub mod commitment;
pub mod error;
pub mod handshake_data;
pub mod handshake_summary;
pub mod notarized_session;
pub mod pubkey;
pub mod session_data;
pub mod session_header;
pub mod session_proof;
pub mod signer;
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
        pubkey::PubKey,
        session_header::{SessionHeader, SessionHeaderMsg},
        session_proof::SessionProof,
        signer::Signer,
        SessionData,
    };
    use p256::ecdsa::{SigningKey, VerifyingKey};
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    #[test]
    fn test() {
        // Notary's signing and verifying key
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let signing_key = SigningKey::random(&mut rng);
        let pubkey = PubKey::P256(VerifyingKey::from(&signing_key));

        let signer = Signer::default();

        // Notary creates the header with SessionHeader::new() (using ::default() here for simplicity)
        let header = SessionHeader::default();

        let signature = header.sign(&signer).unwrap();
        // Notary creates a msg and sends it to User
        // (if the Notary is the Verifier then no signature is required and None is passed)
        let msg = SessionHeaderMsg::new(&header, Some(signature.to_vec()));

        // User verifies the header and stores it with the signature in NotarizedSession
        let header = SessionHeader::from_msg(&msg, Some(&pubkey)).unwrap();
        let signature = msg.signature();

        let data = SessionData::default();
        let session = NotarizedSession::new(1, header, signature, data);

        // User converts NotarizedSession into SessionProof and sends it to the Verifier
        let proof: SessionProof = (&session).into();

        // The Verifier does:
        let SessionProof {
            header,
            handshake_data,
        } = proof;

        // (if the Notary is the Verifier then no pubkey is required and None is passed)
        let header = SessionHeader::from_msg(&header, Some(&pubkey)).unwrap();

        handshake_data.verify(&header, "tlsnotary.org").unwrap();
    }
}
