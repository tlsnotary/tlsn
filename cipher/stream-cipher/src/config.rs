use derive_builder::Builder;

use crate::utils::block_count;

#[derive(Debug, Clone, Copy)]
pub enum Role {
    Leader,
    Follower,
}

#[derive(Debug, Clone, Builder)]
pub struct CounterModeConfig {
    pub(crate) id: String,
    pub(crate) role: Role,
    pub(crate) start_ctr: usize,
    pub(crate) concurrency: usize,
}

#[derive(Debug, Clone, Builder)]
pub struct StreamCipherConfig {
    pub(crate) id: String,
    #[builder(default = "2")]
    pub(crate) start_ctr: usize,
    #[builder(default = "u32::MAX")]
    pub(crate) encoder_default_stream_id: u32,
    #[builder(default = "u32::MAX")]
    pub(crate) encoder_text_stream_id: u32,
    #[builder(default = "8")]
    pub(crate) concurrency: usize,
}

#[derive(Debug)]
pub enum StreamConfig {
    Public { text: Vec<u8> },
    Private { text: Vec<u8> },
    Blind { len: usize },
}

impl StreamConfig {
    pub fn len(&self) -> usize {
        match self {
            StreamConfig::Public { text } => text.len(),
            StreamConfig::Private { text } => text.len(),
            StreamConfig::Blind { len } => *len,
        }
    }

    pub fn to_block_configs(self, block_size: usize) -> Vec<ApplyKeyBlockConfig> {
        match self {
            StreamConfig::Public { text } => text
                .chunks(block_size)
                .map(|block| ApplyKeyBlockConfig::Public {
                    text: block.to_vec(),
                })
                .collect(),
            StreamConfig::Private { text } => text
                .chunks(block_size)
                .map(|block| ApplyKeyBlockConfig::Private {
                    text: block.to_vec(),
                })
                .collect(),
            StreamConfig::Blind { len } => {
                let block_count = block_count(len, block_size);
                (0..block_count)
                    .map(|i| ApplyKeyBlockConfig::Blind {
                        len: if i < block_count - 1 {
                            block_size
                        } else {
                            len % block_size
                        },
                    })
                    .collect()
            }
        }
    }
}

#[derive(Debug)]
pub enum ApplyKeyBlockConfig {
    Public { text: Vec<u8> },
    Private { text: Vec<u8> },
    Blind { len: usize },
}

impl ApplyKeyBlockConfig {
    pub fn len(&self) -> usize {
        match self {
            ApplyKeyBlockConfig::Public { text } => text.len(),
            ApplyKeyBlockConfig::Private { text } => text.len(),
            ApplyKeyBlockConfig::Blind { len } => *len,
        }
    }

    pub fn get_input_text(&self) -> Option<Vec<u8>> {
        match self {
            ApplyKeyBlockConfig::Public { text } => Some(text.clone()),
            ApplyKeyBlockConfig::Private { text } => Some(text.clone()),
            ApplyKeyBlockConfig::Blind { .. } => None,
        }
    }

    pub fn is_private(&self) -> bool {
        match self {
            ApplyKeyBlockConfig::Public { .. } => false,
            ApplyKeyBlockConfig::Private { .. } => true,
            ApplyKeyBlockConfig::Blind { .. } => true,
        }
    }
}
