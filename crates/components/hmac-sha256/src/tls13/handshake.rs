use crate::{
    hmac::{normal::HmacNormal, Hmac},
    kdf::{expand::HkdfExpand, extract::HkdfExtractPrivIkm},
    FError, Mode,
};

use mpz_vm_core::{
    memory::{
        binary::{Binary, U8},
        Array, Vector,
    },
    Vm,
};

// INNER_PARTIAL and OUTER_PARTIAL were computed using the code below:
//
//    // A deterministic derived secret for handshake for SHA-256 ciphersuites.
//    // see https://datatracker.ietf.org/doc/html/draft-ietf-tls-tls13-vectors-06
//    let derived_secret: Vec<u8> = vec![
//        0x6f, 0x26, 0x15, 0xa1, 0x08, 0xc7, 0x02, 0xc5, 0x67, 0x8f, 0x54,
//        0xfc, 0x9d, 0xba, 0xb6, 0x97, 0x16, 0xc0, 0x76, 0x18, 0x9c, 0x48,
//        0x25, 0x0c, 0xeb, 0xea, 0xc3, 0x57, 0x6c, 0x36, 0x11, 0xba];
//
//    let inner_partial = clear::compute_inner_partial(derived_secret.clone());
//    let outer_partial = clear::compute_outer_partial(derived_secret);

/// A deterministic inner partial hash state of the derived secret for
/// handshake for SHA-256 ciphersuites.
const INNER_PARTIAL: [u32; 8] = [
    2335507740, 2200227439, 3546272834, 83913483, 301355998, 2266431524, 1402092146, 439257589,
];

/// A deterministic inner partial hash state of the derived secret for
/// handshake for SHA-256 ciphersuites.
const OUTER_PARTIAL: [u32; 8] = [
    582556975, 2818161237, 3127925320, 2797531207, 4122647441, 3290806166, 3682628262, 2419579842,
];

/// The digest of SHA256("").
const EMPTY_HASH: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// Functionality for computing handshake secrets of TLS 1.3 key schedule.
#[derive(Debug)]
pub(crate) struct HandshakeSecrets {
    mode: Mode,
    state: State,
    handshake_secret: Option<HkdfExtractPrivIkm>,
    client_secret: Option<HkdfExpand>,
    server_secret: Option<HkdfExpand>,
    derived_secret: Option<HkdfExpand>,
}

impl HandshakeSecrets {
    /// Creates a new functionality.
    pub(crate) fn new(mode: Mode) -> HandshakeSecrets {
        Self {
            mode,
            state: State::Initialized,
            handshake_secret: None,
            client_secret: None,
            server_secret: None,
            derived_secret: None,
        }
    }

    /// Allocates the functionality with the given pre-master secret.
    ///
    /// Returns client_handshake_traffic_secret,
    /// server_handshake_traffic_secret, and derived_secret for master_secret.
    #[allow(clippy::type_complexity)]
    pub(crate) fn alloc(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        pms: Array<U8, 32>,
    ) -> Result<(Array<U8, 32>, Array<U8, 32>, Vector<U8>), FError> {
        let State::Initialized = self.state.take() else {
            return Err(FError::state("not in Initialized state"));
        };

        let mode = self.mode;
        let hmac = HmacNormal::alloc_with_state(vm, INNER_PARTIAL, OUTER_PARTIAL)?;

        let handshake_secret = HkdfExtractPrivIkm::alloc(vm, pms, hmac)?;

        let hmac_hs1 = Hmac::alloc(vm, handshake_secret.output(), mode)?;
        let hmac_hs2 = Hmac::from_other(vm, &hmac_hs1)?;
        let hmac_hs3 = Hmac::from_other(vm, &hmac_hs1)?;

        let client_secret = HkdfExpand::alloc(mode, vm, hmac_hs1, b"c hs traffic", None, 32, 32)?;

        let server_secret = HkdfExpand::alloc(mode, vm, hmac_hs2, b"s hs traffic", None, 32, 32)?;

        // Optimization: by computing now the derived_secret for
        // master_secret in parallel with cs and ss, we save communication
        // rounds when we are in the reduced mode.
        let derived_secret =
            HkdfExpand::alloc(mode, vm, hmac_hs3, b"derived", Some(&EMPTY_HASH), 32, 32)?;

        let cs_out: Array<U8, 32> = client_secret
            .output()
            .try_into()
            .expect("client secret is 32 bytes");
        let ss_out = server_secret
            .output()
            .try_into()
            .expect("server secret is 32 bytes");

        let derived_output = derived_secret.output();

        self.handshake_secret = Some(handshake_secret);
        self.client_secret = Some(client_secret);
        self.server_secret = Some(server_secret);
        self.derived_secret = Some(derived_secret);
        self.state = State::WantsHelloHash;

        Ok((cs_out, ss_out, derived_output))
    }

    /// Whether this functionality needs to be flushed.
    pub(crate) fn wants_flush(&self) -> bool {
        let client_secret = self.client_secret.as_ref().expect("functionality was set");
        let server_secret = self.server_secret.as_ref().expect("functionality was set");
        let derived_secret = self.derived_secret.as_ref().expect("functionality was set");
        let handshake_secret = self
            .handshake_secret
            .as_ref()
            .expect("functionality was set");

        let state_wants_flush = matches!(&self.state, State::HelloHashSet(..));

        state_wants_flush
            || client_secret.wants_flush()
            || server_secret.wants_flush()
            || derived_secret.wants_flush()
            || handshake_secret.wants_flush()
    }

    /// Flushes the functionality.
    pub(crate) fn flush(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), FError> {
        let client_secret = self.client_secret.as_mut().expect("functionality was set");
        let server_secret = self.server_secret.as_mut().expect("functionality was set");
        let derived_secret = self.derived_secret.as_mut().expect("functionality was set");
        let handshake_secret = self
            .handshake_secret
            .as_mut()
            .expect("functionality was set");

        client_secret.flush(vm)?;
        derived_secret.flush(vm)?;
        handshake_secret.flush();
        server_secret.flush(vm)?;

        if let State::HelloHashSet(hash) = &mut self.state {
            client_secret.set_ctx(hash)?;
            client_secret.flush(vm)?;

            server_secret.set_ctx(hash)?;
            server_secret.flush(vm)?;

            if handshake_secret.is_complete()
                && client_secret.is_complete()
                && server_secret.is_complete()
                && derived_secret.is_complete()
            {
                self.state = State::Complete;
            }
        }

        Ok(())
    }

    /// Sets the hash of the ClientHello message.
    pub(crate) fn set_hello_hash(&mut self, hello_hash: [u8; 32]) -> Result<(), FError> {
        match &mut self.state {
            State::WantsHelloHash => {
                self.state = State::HelloHashSet(hello_hash);
                Ok(())
            }
            _ => Err(FError::state("not in WantsHelloHash state")),
        }
    }

    /// Whether this functionality is complete.
    pub(crate) fn is_complete(&self) -> bool {
        matches!(self.state, State::Complete)
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(crate) enum State {
    Initialized,
    WantsHelloHash,
    HelloHashSet([u8; 32]),
    Complete,
    Error,
}

impl State {
    pub(crate) fn take(&mut self) -> State {
        std::mem::replace(self, State::Error)
    }
}
