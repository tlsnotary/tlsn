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
    /// connection will be decrypted for free.
    pub(crate) max_recv_online: usize,
    /// Maximum number of received bytes.
    #[allow(unused)]
    pub(crate) max_recv: usize,
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
                .ok_or(ConfigBuilderError::UninitializedField("max_sent"))?;
        let max_recv_online = MIN_RECV
            + self
                .max_recv_online
                .ok_or(ConfigBuilderError::UninitializedField("max_recv_online"))?;
        let max_recv = self
            .max_recv
            .ok_or(ConfigBuilderError::UninitializedField("max_recv"))?;

        if max_recv_online > max_recv {
            return Err(ConfigBuilderError::ValidationError(
                "max_recv_online must be less than or equal to max_recv".to_string(),
            ));
        }

        let max_sent_records = self
            .max_sent_records
            .unwrap_or_else(|| MIN_SENT_RECORDS + max_sent.div_ceil(16384));
        let max_recv_records = self
            .max_recv_records
            .unwrap_or_else(|| MIN_RECV_RECORDS + max_recv.div_ceil(16384));

        Ok(Config {
            defer_decryption,
            max_sent_records,
            max_sent,
            max_recv_records,
            max_recv_online,
            max_recv,
        })
    }
}
