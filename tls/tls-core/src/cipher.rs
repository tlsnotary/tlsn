use elliptic_curve::{Curve, SecretKey};

pub trait Tls12AeadAlgorithm: Send + Sync + 'static {
    type Curve: Curve;
    type Decrypter;
    type Encrypter;
    fn decrypter(&self, key: SecretKey<Self::Curve>, iv: &[u8]) -> Box<Self::Decrypter>;
    fn encrypter(
        &self,
        key: SecretKey<Self::Curve>,
        iv: &[u8],
        extra: &[u8],
    ) -> Box<Self::Encrypter>;
}

pub trait Tls13AeadAlgorithm: Send + Sync + 'static {
    type Curve: Curve;
    type Decrypter;
    type Encrypter;
    fn decrypter(&self, key: SecretKey<Self::Curve>, iv: &[u8]) -> Box<Self::Decrypter>;
    fn encrypter(
        &self,
        key: SecretKey<Self::Curve>,
        iv: &[u8],
        extra: &[u8],
    ) -> Box<Self::Encrypter>;
}
