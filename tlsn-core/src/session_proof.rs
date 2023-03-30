use crate::{
    handshake_data::HandshakeDataMsg, notarized_session::NotarizedSession,
    session_header::SessionHeaderMsg,
};

pub struct SessionProof {
    header: SessionHeaderMsg,
    handshake_data: HandshakeDataMsg,
}

impl From<&NotarizedSession> for SessionProof {
    fn from(session: &NotarizedSession) -> SessionProof {
        SessionProof {
            header: SessionHeaderMsg::new(session.header(), session.signature().clone()),
            handshake_data: HandshakeDataMsg::from(session.data().handshake_data().clone()),
        }
    }
}
