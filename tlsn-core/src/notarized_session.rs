use serde::Serialize;

use crate::{session_data::SessionData, session_header::SessionHeader, signature::Signature};

#[derive(Serialize)]
pub struct NotarizedSession {
    version: u8,
    header: SessionHeader,
    signature: Option<Signature>,
    data: SessionData,
}

impl NotarizedSession {
    pub fn new(
        version: u8,
        header: SessionHeader,
        signature: Option<Signature>,
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

    pub fn signature(&self) -> &Option<Signature> {
        &self.signature
    }

    pub fn data(&self) -> &SessionData {
        &self.data
    }
}
