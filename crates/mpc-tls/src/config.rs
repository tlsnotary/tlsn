use derive_builder::Builder;

/// Number of TLS protocol bytes that will be sent.
const PROTOCOL_DATA_SENT: usize = 32;
/// Number of TLS protocol bytes that will be received.
const PROTOCOL_DATA_RECV: usize = 32;

/// Number of TLS protocol records that we need to allocate in addition
/// to the application data records.
const PROTOCOL_RECORD_COUNT_SENT: usize = 2;
/// Number of TLS protocol records that we need to allocate in addition
/// to the application data records.
const PROTOCOL_RECORD_COUNT_RECV: usize = 2;

/// Computes the record count configuration given the data volume.
///
/// Accurately estimating a good default is challenging as we do not
/// know exactly how much data will be packed into each record in advance.
fn default_record_count(max_data: usize) -> usize {
    // We assume a minimum of 8 records for the first 4KB.
    const MIN: usize = 8;

    // Then we estimate that after 4KB of data is transmitted that they will
    // average 4KB in size.
    let remainder = max_data.saturating_sub(4096);
    let count = remainder.div_ceil(4096);

    // For example, if max_data=32KB then this will return 15. That will result
    // in about 3MB upload from prover to verifier.
    MIN + count
}

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
        let max_sent = PROTOCOL_DATA_SENT
            + self
                .max_sent
                .ok_or(ConfigBuilderError::UninitializedField("max_sent"))?;
        let mut max_recv_online = self
            .max_recv_online
            .ok_or(ConfigBuilderError::UninitializedField("max_recv_online"))?;
        let mut max_recv = self
            .max_recv
            .ok_or(ConfigBuilderError::UninitializedField("max_recv"))?;

        if max_recv_online > max_recv {
            return Err(ConfigBuilderError::ValidationError(
                "max_recv_online must be less than or equal to max_recv".to_string(),
            ));
        }

        max_recv_online += PROTOCOL_DATA_RECV;
        max_recv += PROTOCOL_DATA_RECV;

        let max_sent_records = self
            .max_sent_records
            .unwrap_or_else(|| PROTOCOL_RECORD_COUNT_SENT + default_record_count(max_sent));
        let max_recv_records = self
            .max_recv_records
            .unwrap_or_else(|| PROTOCOL_RECORD_COUNT_RECV + default_record_count(max_recv));

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_record_count() {
        assert_eq!(default_record_count(1 << 15), 15);
    }
}
