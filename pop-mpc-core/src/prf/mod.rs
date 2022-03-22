pub mod master;
mod sha;
pub mod slave;

use hmac::Hmac;
use sha2::Sha256;

pub use master::PrfMaster;
pub use slave::PrfSlave;

type H = Hmac<Sha256>;

#[cfg(test)]
mod tests {
    use super::*;
}
