use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    pub vk: Vec<u8>,
    pub proof: Vec<u8>,
    pub check_date: String,
}
