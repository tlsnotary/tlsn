use crate::{session_data::SessionData, session_header::SessionHeader};

pub struct NotarizedSession {
    version: u8,
    header: SessionHeader,
    signature: Option<Vec<u8>>,
    data: SessionData,
}

impl NotarizedSession {
    pub fn new(
        version: u8,
        header: SessionHeader,
        signature: Option<Vec<u8>>,
        data: SessionData,
    ) -> Self {
        Self {
            version,
            header,
            signature,
            data,
        }
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn header(&self) -> &SessionHeader {
        &self.header
    }

    pub fn signature(&self) -> &Option<Vec<u8>> {
        &self.signature
    }

    pub fn data(&self) -> &SessionData {
        &self.data
    }
}
