use crate::error::Error;
use p256::{ecdh::EphemeralSecret, PublicKey};
use tls_core::msgs::enums::NamedGroup;

/// An in-progress key exchange.  This has the algorithm,
/// our private key, and our public key.
pub(crate) struct KeyExchange {
    skxg: &'static SupportedKxGroup,
    privkey: EphemeralSecret,
    pub(crate) pubkey: PublicKey,
}

impl KeyExchange {
    /// Choose a SupportedKxGroup by name, from a list of supported groups.
    pub(crate) fn choose(
        name: NamedGroup,
        supported: &[&'static SupportedKxGroup],
    ) -> Option<&'static SupportedKxGroup> {
        supported.iter().find(|skxg| skxg.name == name).cloned()
    }

    /// Start a key exchange, using the given SupportedKxGroup.
    ///
    /// This generates an ephemeral key pair and stores it in the returned KeyExchange object.
    pub(crate) fn start(skxg: &'static SupportedKxGroup) -> Option<Self> {
        // We only support secp256r1 for now.
        if !matches!(skxg.name, NamedGroup::secp256r1) {
            return None;
        }

        let ours = EphemeralSecret::random(&mut rand::rngs::OsRng);

        let pubkey = ours.public_key();

        Some(Self {
            skxg,
            privkey: ours,
            pubkey,
        })
    }

    /// Return the group being used.
    pub(crate) fn group(&self) -> NamedGroup {
        self.skxg.name
    }

    /// Completes the key exchange, given the peer's public key.
    ///
    /// The shared secret is passed into the closure passed down in `f`, and the result of calling
    /// `f` is returned to the caller.
    pub(crate) fn complete<T>(
        self,
        peer: &[u8],
        f: impl FnOnce(&[u8]) -> Result<T, ()>,
    ) -> Result<T, Error> {
        let peer_key = PublicKey::from_sec1_bytes(peer).map_err(|_| {
            Error::PeerMisbehavedError("parsing peer's public key failed".to_string())
        })?;

        let shared_secret = self.privkey.diffie_hellman(&peer_key);

        f(shared_secret.raw_secret_bytes())
            .map_err(|()| Error::PeerMisbehavedError("key agreement failed".to_string()))
    }
}

/// A key-exchange group supported by rustls.
///
/// All possible instances of this class are provided by the library in
/// the `ALL_KX_GROUPS` array.
#[derive(Debug)]
pub struct SupportedKxGroup {
    /// The IANA "TLS Supported Groups" name of the group
    pub name: NamedGroup,
}

/// Ephemeral ECDH on curve25519 (see RFC7748)
pub static X25519: SupportedKxGroup = SupportedKxGroup {
    name: NamedGroup::X25519,
};

/// Ephemeral ECDH on secp256r1 (aka NIST-P256)
pub static SECP256R1: SupportedKxGroup = SupportedKxGroup {
    name: NamedGroup::secp256r1,
};

/// Ephemeral ECDH on secp384r1 (aka NIST-P384)
pub static SECP384R1: SupportedKxGroup = SupportedKxGroup {
    name: NamedGroup::secp384r1,
};

/// A list of all the key exchange groups supported by rustls.
pub static ALL_KX_GROUPS: [&SupportedKxGroup; 1] = [
    // &X25519,
    &SECP256R1,
    // &SECP384R1
];
