use crate::{
    hmac::Hmac,
    kdf::expand::{HkdfExpand, EMPTY_CTX},
    ApplicationKeys, FError, Mode,
};

use mpz_vm_core::{
    memory::{
        binary::{Binary, U8},
        Vector,
    },
    Vm,
};

/// Functionality for computing application secrets of TLS 1.3 key schedule.
#[derive(Debug)]
pub(crate) struct ApplicationSecrets {
    mode: Mode,
    state: State,
    client_secret: Option<HkdfExpand>,
    server_secret: Option<HkdfExpand>,
    client_application_key: Option<HkdfExpand>,
    client_application_iv: Option<HkdfExpand>,
    server_application_key: Option<HkdfExpand>,
    server_application_iv: Option<HkdfExpand>,
}

impl ApplicationSecrets {
    /// Creates a new functionality.
    pub(crate) fn new(mode: Mode) -> ApplicationSecrets {
        Self {
            mode,
            state: State::Initialized,
            client_secret: None,
            server_secret: None,
            client_application_key: None,
            client_application_iv: None,
            server_application_key: None,
            server_application_iv: None,
        }
    }

    /// Allocates the functionality with the given `master_secret`.
    pub(crate) fn alloc(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        master_secret: Vector<U8>,
    ) -> Result<(), FError> {
        let State::Initialized = self.state.take() else {
            return Err(FError::state("not in Initialized state"));
        };

        let mode = self.mode;

        let hmac_ms1 = Hmac::alloc(vm, master_secret, mode)?;
        let hmac_ms2 = Hmac::from_other(vm, &hmac_ms1)?;

        let client_secret = HkdfExpand::alloc(mode, vm, hmac_ms1, b"c ap traffic", None, 32, 32)?;

        let server_secret = HkdfExpand::alloc(mode, vm, hmac_ms2, b"s ap traffic", None, 32, 32)?;

        let hmac_cs1 = Hmac::alloc(vm, client_secret.output(), mode)?;
        let hmac_cs2 = Hmac::from_other(vm, &hmac_cs1)?;

        let hmac_ss1 = Hmac::alloc(vm, server_secret.output(), mode)?;
        let hmac_ss2 = Hmac::from_other(vm, &hmac_ss1)?;

        let client_application_key =
            HkdfExpand::alloc(mode, vm, hmac_cs1, b"key", Some(&EMPTY_CTX), 0, 16)?;

        let client_application_iv =
            HkdfExpand::alloc(mode, vm, hmac_cs2, b"iv", Some(&EMPTY_CTX), 0, 12)?;

        let server_application_key =
            HkdfExpand::alloc(mode, vm, hmac_ss1, b"key", Some(&EMPTY_CTX), 0, 16)?;

        let server_application_iv =
            HkdfExpand::alloc(mode, vm, hmac_ss2, b"iv", Some(&EMPTY_CTX), 0, 12)?;

        self.state = State::WantsHandshakeHash;
        self.client_secret = Some(client_secret);
        self.server_secret = Some(server_secret);
        self.client_application_key = Some(client_application_key);
        self.client_application_iv = Some(client_application_iv);
        self.server_application_key = Some(server_application_key);
        self.server_application_iv = Some(server_application_iv);

        Ok(())
    }

    /// Whether this functionality needs to be flushed.
    pub(crate) fn wants_flush(&self) -> bool {
        let client_secret = self.client_secret.as_ref().expect("functionality was set");
        let server_secret = self.server_secret.as_ref().expect("functionality was set");
        let client_application_key = self
            .client_application_key
            .as_ref()
            .expect("functionality was set");
        let client_application_iv = self
            .client_application_iv
            .as_ref()
            .expect("functionality was set");
        let server_application_key = self
            .server_application_key
            .as_ref()
            .expect("functionality was set");
        let server_application_iv = self
            .server_application_iv
            .as_ref()
            .expect("functionality was set");

        let state_wants_flush = matches!(&self.state, State::HandshakeHashSet(..));

        state_wants_flush
            || client_secret.wants_flush()
            || server_secret.wants_flush()
            || client_application_key.wants_flush()
            || client_application_iv.wants_flush()
            || server_application_key.wants_flush()
            || server_application_iv.wants_flush()
    }

    /// Flushes the functionality.
    pub(crate) fn flush(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), FError> {
        let client_secret = self.client_secret.as_mut().expect("functionality was set");
        let server_secret = self.server_secret.as_mut().expect("functionality was set");
        let client_application_key = self
            .client_application_key
            .as_mut()
            .expect("functionality was set");
        let client_application_iv = self
            .client_application_iv
            .as_mut()
            .expect("functionality was set");
        let server_application_key = self
            .server_application_key
            .as_mut()
            .expect("functionality was set");
        let server_application_iv = self
            .server_application_iv
            .as_mut()
            .expect("functionality was set");

        client_secret.flush(vm)?;
        server_secret.flush(vm)?;
        client_application_key.flush(vm)?;
        client_application_iv.flush(vm)?;
        server_application_key.flush(vm)?;
        server_application_iv.flush(vm)?;

        if let State::HandshakeHashSet(hash) = &self.state {
            if !client_secret.is_ctx_set() {
                client_secret.set_ctx(hash)?;
                client_secret.flush(vm)?;
            }
            if !server_secret.is_ctx_set() {
                server_secret.set_ctx(hash)?;
                server_secret.flush(vm)?;
            }

            if client_application_iv.is_complete()
                && client_application_key.is_complete()
                && client_secret.is_complete()
                && server_application_iv.is_complete()
                && server_application_key.is_complete()
                && server_secret.is_complete()
            {
                self.state = State::Complete(ApplicationKeys {
                    client_write_key: client_application_key
                        .output()
                        .try_into()
                        .expect("key length is 16 bytes"),
                    client_iv: client_application_iv
                        .output()
                        .try_into()
                        .expect("iv length is 12 bytes"),
                    server_write_key: server_application_key
                        .output()
                        .try_into()
                        .expect("key length is 16 bytes"),
                    server_iv: server_application_iv
                        .output()
                        .try_into()
                        .expect("iv length is 12 bytes"),
                });
            }
        }

        Ok(())
    }

    /// Sets the handshake hash.
    pub(crate) fn set_handshake_hash(&mut self, handshake_hash: [u8; 32]) -> Result<(), FError> {
        match &mut self.state {
            State::WantsHandshakeHash => {
                self.state = State::HandshakeHashSet(handshake_hash);
                Ok(())
            }
            _ => Err(FError::state("not in WantsHandshakeHash state")),
        }
    }

    /// Returns the application keys.
    pub(crate) fn keys(&mut self) -> Result<ApplicationKeys, FError> {
        match self.state {
            State::Complete(keys) => Ok(keys),
            _ => Err(FError::state("not in Complete state")),
        }
    }

    /// Whether this functionality is complete.
    pub(crate) fn is_complete(&self) -> bool {
        matches!(self.state, State::Complete { .. })
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(crate) enum State {
    Initialized,
    /// Wants handshake hash to be set.
    WantsHandshakeHash,
    /// Handshake hash has been set.
    HandshakeHashSet([u8; 32]),
    Complete(ApplicationKeys),
    Error,
}

impl State {
    pub(crate) fn take(&mut self) -> State {
        std::mem::replace(self, State::Error)
    }
}
