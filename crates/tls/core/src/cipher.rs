use crate::msgs::enums::{ContentType, ProtocolVersion};

pub fn make_tls12_aad(seq: u64, typ: ContentType, vers: ProtocolVersion, len: usize) -> [u8; 13] {
    let mut aad = [0u8; 13];
    aad[..8].copy_from_slice(&seq.to_be_bytes());
    aad[8] = typ.get_u8();
    aad[9..11].copy_from_slice(&vers.get_u16().to_be_bytes());
    aad[11..13].copy_from_slice(&(len as u16).to_be_bytes());
    aad
}
