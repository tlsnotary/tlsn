use std::sync::Arc;

use tls_client::ClientConfig;

pub struct WantsRole;
pub struct WantsClientConfig {}

/// ConnectionMaster configuration
pub struct MasterConfig {
    pub client: Arc<ClientConfig>,
    pub probe_server: bool,
}

impl MasterConfig {
    pub fn builder() -> ConfigBuilder<WantsClientConfig> {
        ConfigBuilder::master()
    }
}

pub struct ConfigBuilder<T = WantsRole> {
    state: T,
}

impl ConfigBuilder<WantsRole> {
    pub fn master() -> ConfigBuilder<WantsClientConfig> {
        ConfigBuilder {
            state: WantsClientConfig {},
        }
    }
}

impl ConfigBuilder<WantsClientConfig> {
    pub fn client_config(self, config: Arc<ClientConfig>) -> MasterConfig {
        MasterConfig {
            client: config,
            probe_server: true,
        }
    }
}
