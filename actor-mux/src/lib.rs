//! This crate provides stream multiplexer implementations built using the actor pattern.

pub mod mock;
pub mod yamux;

pub use self::yamux::{YamuxConfig, YamuxMuxControl, YamuxMuxer};
