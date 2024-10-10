//! Types for the AuthDecode protocol.

use core::ops::Range;

use crate::{
    hash::HashAlgId,
    request::Request,
    transcript::{
        encoding::EncodingProvider,
        Transcript,
    },
    Secrets,
};

use super::Direction;

/// The list of hash algorithms compatible with AuthDecode.
const COMPATIBLE_ALGS: &[HashAlgId] = &[HashAlgId::POSEIDON_HALO2];

/// A batch of AuthDecode inputs with the hash algorithm.
pub struct AuthdecodeInputsWithAlg {
    /// A batch of AuthDecode inputs.
    pub inputs: AuthdecodeInputs,
    /// The hash algorithm used to create AuthDecode commitments.
    pub alg: HashAlgId,
}

impl AuthdecodeInputsWithAlg {
    /// Returns the total bytesize of committed plaintext in all inputs.
    pub fn total_plaintext(&self) -> usize {
        self.inputs
            .0
            .iter()
            .map(|input| input.plaintext.len())
            .sum()
    }
}

/// A batch of AuthDecode inputs.  
pub struct AuthdecodeInputs(Vec<AuthDecodeInput>);

impl AuthdecodeInputs {
    /// Consumes self, returning the inner vector.
    pub fn to_inner(self) -> Vec<AuthDecodeInput> {
        self.0
    }
}

/// An AuthDecode input to prove a single range of a TLS transcript. Also contains the `salt` to be
/// used for the plaintext commitment.
pub struct AuthDecodeInput {
    /// The salt of the plaintext commitment.
    pub salt: [u8; 16],
    /// The plaintext to commit to.
    pub plaintext: Vec<u8>,
    /// The encodings to commit to in MSB0 bit order.
    pub encodings: Vec<Vec<u8>>,
    /// The byterange of the plaintext.
    pub range: Range<usize>,
    /// The direction of the range in the transcript.
    pub direction: Direction
}

impl AuthDecodeInput {
    /// Creates a new `AuthDecodeInput`.
    /// 
    /// # Panics
    /// 
    /// Panics if some of the arguments are not correct. 
    fn new(salt: [u8; 16], plaintext: Vec<u8>, encodings: Vec<Vec<u8>>, range: Range<usize>, direction:Direction) -> Self {
            assert!(!range.is_empty());
            assert!(plaintext.len()*8 == encodings.len());
            assert!(plaintext.len() == range.len());
            // All encodings should have the same length.
            for pair in encodings.windows(2) {
                assert!(pair[0].len() == pair[1].len());
            }
            Self {
                salt,
                plaintext,
                encodings,
                range,
                direction
            }
        }
}

/// The hash algorithm used in AuthDecode.
pub struct AuthDecodeAlg(HashAlgId);

impl AuthDecodeAlg {
    /// Returns the hash algorithm used in AuthDecode.
    pub fn alg(&self) -> &HashAlgId {
        &self.0
    }
}

impl TryFrom<&Request> for AuthDecodeAlg {
    type Error = &'static str;

    fn try_from(request: &Request) -> Result<Self, Self::Error> {
        let mut hash_alg: Option<HashAlgId> = None;

        if let Some(hashes) = &request.plaintext_hashes {
            for hash in hashes {
                if COMPATIBLE_ALGS.contains(&hash.hash.alg) {
                    if hash_alg.is_none() {
                        hash_alg = Some(hash.hash.alg);
                    } else if hash_alg != Some(hash.hash.alg) {
                        return Err(
                        "Only a single AuthDecode-compatible hash algorithm is allowed in commitments",
                    );
                    }
                }
            }
        };

        if hash_alg.is_none() {
            return Err("At least one AuthDecode-compatible hash commitment is expected");
        }

        Ok(AuthDecodeAlg(
            hash_alg.expect("Hash algorithm should be set"),
        ))
    }
}

impl
    TryFrom<(
        &Request,
        &Secrets,
        &(dyn EncodingProvider + Send + Sync),
        &Transcript,
    )> for AuthdecodeInputsWithAlg
{
    type Error = String;

    fn try_from(
        tuple: (
            &Request,
            &Secrets,
            &(dyn EncodingProvider + Send + Sync),
            &Transcript,
        ),
    ) -> Result<Self, Self::Error> {
        let (request, secrets, encoding_provider, transcript) = tuple;

        let mut hash_alg: Option<HashAlgId> = None;

        let inputs = if let (Some(hashes), Some(hash_secrets)) =
            (&request.plaintext_hashes, &secrets.plaintext_hash_secrets)
        {
            hashes
                .iter()
                .filter(|hash| COMPATIBLE_ALGS.contains(&hash.hash.alg))
                .map(|hash| {
                    if hash_alg.is_none() {
                        hash_alg = Some(hash.hash.alg);
                    } else if hash_alg != Some(hash.hash.alg) {
                        return Err(
                        "Only a single AuthDecode-compatible hash algorithm is allowed in commitments".to_string());
                    }
             
                    let blinder = hash_secrets
                        .get_by_transcript_idx(&hash.direction, &hash.idx)
                        .ok_or(format!("direction {} and index {:?} were not found in the secrets", &hash.direction, &hash.idx))?
                        .blinder
                        .clone();

                    let plaintext = transcript.get(hash.direction, &hash.idx).ok_or(format!("direction {} and index {:?} were not found in the transcript", &hash.direction, &hash.idx))?.data().to_vec();
                    
                    let mut encodings = encoding_provider
                        .provide_bit_encodings(hash.direction, &hash.idx).ok_or(format!("direction {} and index {:?} were not found by the encoding provider", &hash.direction, &hash.idx))?;
                    // Reverse encodings to MSB0.
                    for chunk in encodings.chunks_mut(8) {
                        chunk.reverse();
                    }

                    Ok(AuthDecodeInput::new(*blinder.as_inner(), plaintext, encodings,
                        hash.idx.iter_ranges().next().expect("A range should be present in a rangeset"),
                        hash.direction))
                })
                .collect::<Result<Vec<_>, Self::Error>>()?
        } else {
            Vec::new()
        };

        if inputs.is_empty() {
            return Err("At least one AuthDecode-compatible hash commitment is expected".to_string());
        }

        Ok(AuthdecodeInputsWithAlg {
            inputs: AuthdecodeInputs(inputs),
            alg: hash_alg.expect("Hash algorithm should be set"),
        })
    }
}
