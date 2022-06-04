use std::ops::{Deref, DerefMut};

use crate::Error;
use tls_core::msgs::handshake::Random;

use async_trait::async_trait;

#[async_trait]
pub trait Handshake: Send + Sync {
    /// Returns client_random value for session
    async fn client_random(&mut self) -> Result<Random, Error>;
}

pub struct Handshaker {
    inner: Box<dyn Handshake + Send + Sync>,
}

impl Deref for Handshaker {
    type Target = Box<dyn Handshake + Send + Sync>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Handshaker {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Handshaker {
    pub fn new() -> Self {
        Self {
            //inner: <dyn Handshake>::invalid(),
            inner: Box::new(RingHandshaker {}),
        }
    }

    pub fn set_inner(&mut self, inner: Box<dyn Handshake + Send + Sync>) {
        self.inner = inner;
    }
}

pub struct RingHandshaker {}

#[async_trait]
impl Handshake for RingHandshaker {
    async fn client_random(&mut self) -> Result<Random, Error> {
        Ok(Random::new()?)
    }
}

pub struct InvalidHandShaker {}

#[async_trait]
impl Handshake for InvalidHandShaker {
    async fn client_random(&mut self) -> Result<Random, Error> {
        Err(Error::General("handshaker not yet available".to_string()))
    }
}

impl dyn Handshake {
    pub(crate) fn invalid() -> Box<dyn Handshake + Send + Sync> {
        Box::new(InvalidHandShaker {})
    }
}
