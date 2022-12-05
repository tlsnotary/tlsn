//! This crate provides stream multiplexer implementations built using the actor pattern.

#[cfg(feature = "mock")]
pub mod mock;
#[cfg(feature = "yamux")]
pub mod yamux;

#[cfg(feature = "yamux")]
pub use self::yamux::{YamuxConfig, YamuxMuxControl, YamuxMuxer};
#[cfg(feature = "mock")]
pub use mock::{
    MockClientChannelMuxer, MockClientControl, MockServerChannelMuxer, MockServerControl,
};
