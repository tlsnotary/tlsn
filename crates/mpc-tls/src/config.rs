use derive_builder::Builder;

const MIN_SENT: usize = 32;
const MIN_SENT_RECORDS: usize = 8;
const MIN_RECV: usize = 32;
const MIN_RECV_RECORDS: usize = 8;

/// MPC-TLS configuration.
#[derive(Debug, Clone, Builder)]
#[builder(build_fn(skip))]
pub struct Config {
    /// Defers decryption of received data until after the MPC-TLS connection is
    /// closed.
    ///
    /// The received data will be decrypted locally without MPC, thus improving
    /// bandwidth usage and performance.
    pub(crate) defer_decryption: bool,
    /// Maximum number of sent TLS records. Data is transmitted in records up to
    /// 16KB long.
    pub(crate) max_sent_records: usize,
    /// Maximum number of sent bytes.
    pub(crate) max_sent: usize,
    /// Maximum number of received TLS records. Data is transmitted in records
    /// up to 16KB long.
    pub(crate) max_recv_records: usize,
    /// Maximum number of received bytes which will be decrypted while
    /// the TLS connection is active. Data which can be decrypted after the TLS
    /// connection will be decrypted for free. If `defer_decryption` is set to
    /// `false` this field must be specified.
    pub(crate) max_recv_online: usize,
}

impl Config {
    /// Creates a new builder.
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }
}

impl ConfigBuilder {
    /// Builds the configuration.
    pub fn build(&self) -> Result<Config, ConfigBuilderError> {
        let defer_decryption = self.defer_decryption.unwrap_or(true);
        let max_sent = MIN_SENT
            + self
                .max_sent
                .ok_or_else(|| ConfigBuilderError::UninitializedField("max_sent"))?;
        let max_recv_online = if defer_decryption {
            MIN_RECV
        } else {
            self.max_recv_online
                .ok_or(ConfigBuilderError::UninitializedField("max_recv_online"))?
        };

        let max_sent_records = self
            .max_sent_records
            .unwrap_or_else(|| MIN_SENT_RECORDS + max_sent.div_ceil(16384));
        let max_recv_records = self
            .max_recv_records
            .unwrap_or_else(|| MIN_RECV_RECORDS + max_recv_online.div_ceil(16384));

        Ok(Config {
            defer_decryption,
            max_sent_records,
            max_sent,
            max_recv_records,
            max_recv_online,
        })
    }
}
