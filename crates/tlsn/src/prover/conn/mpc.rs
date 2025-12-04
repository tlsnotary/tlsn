use futures_plex::DuplexStream;

/// A connection to the verifier.
pub struct MpcConnection {
    duplex: DuplexStream,
}

impl MpcConnection {
    pub(crate) fn new(duplex: DuplexStream) -> Self {
        Self { duplex }
    }
}
