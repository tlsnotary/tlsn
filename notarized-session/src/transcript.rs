/// A transcript consists of all bytes which were sent and all bytes which were received
pub struct Transcript {
    sent: Vec<u8>,
    received: Vec<u8>,
}

impl Transcript {
    pub fn new(sent: Vec<u8>, received: Vec<u8>) -> Self {
        Self { sent, received }
    }

    pub fn sent(&self) -> &Vec<u8> {
        &self.sent
    }

    pub fn received(&self) -> &Vec<u8> {
        &self.received
    }
}
