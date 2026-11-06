//! Per-direction close state for the prover's TLS connection.
//!
//! TLS closes each direction independently, so the connection is modelled as
//! two monotonic state machines: outbound (application to server) and inbound
//! (server to application). A single predicate over both decides when the
//! protocol may finalize.

/// State of the outbound half: bytes the application sends to the server.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Outbound {
    /// The application may still write.
    #[default]
    Open,
    /// The application asked to close; our close_notify is being produced.
    Closing,
    /// Every outbound byte, including close_notify, has been handed to the
    /// transport.
    Flushed,
    /// The transport write half is closed.
    Closed,
}

/// State of the inbound half: bytes the server sends to the application.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Inbound {
    /// The peer may still send.
    #[default]
    Open,
    /// The peer finished its TLS stream (close_notify or transport EOF).
    PeerClosed,
    /// All decrypted plaintext has been handed to the application.
    Drained,
    /// EOF has been queued for the application.
    EofDelivered,
}

/// Monotonic close state for both directions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct CloseState {
    outbound: Outbound,
    inbound: Inbound,
}

impl CloseState {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Returns whether the application has asked to close its side.
    pub(crate) fn close_requested(&self) -> bool {
        self.outbound >= Outbound::Closing
    }

    /// Returns whether the peer has finished sending.
    pub(crate) fn peer_closed(&self) -> bool {
        self.inbound >= Inbound::PeerClosed
    }

    /// Returns whether everything outbound has been handed to the transport.
    pub(crate) fn outbound_flushed(&self) -> bool {
        self.outbound >= Outbound::Flushed
    }

    /// Returns whether all inbound plaintext has been delivered to the app.
    pub(crate) fn inbound_drained(&self) -> bool {
        self.inbound >= Inbound::Drained
    }

    /// Returns whether EOF has been queued for the application.
    pub(crate) fn eof_delivered(&self) -> bool {
        self.inbound == Inbound::EofDelivered
    }

    pub(crate) fn mark_close_requested(&mut self) {
        self.advance_outbound(Outbound::Closing);
    }

    /// Outbound bytes and close_notify have been handed to the transport.
    pub(crate) fn mark_outbound_flushed(&mut self) {
        self.advance_outbound(Outbound::Flushed);
    }

    /// The transport write half has been closed.
    pub(crate) fn mark_outbound_closed(&mut self) {
        self.advance_outbound(Outbound::Closed);
    }

    /// The peer finished its TLS stream.
    pub(crate) fn mark_peer_closed(&mut self) {
        self.advance_inbound(Inbound::PeerClosed);
    }

    /// All decrypted plaintext has been delivered to the application.
    pub(crate) fn mark_drained(&mut self) {
        self.advance_inbound(Inbound::Drained);
    }

    /// EOF has been queued for the application.
    pub(crate) fn mark_eof_delivered(&mut self) {
        self.advance_inbound(Inbound::EofDelivered);
    }

    /// Returns whether the protocol may finalize.
    ///
    /// Both sides must have finished: every outbound byte handed to the
    /// transport, and every inbound plaintext byte delivered to the
    /// application.
    pub(crate) fn can_finalize(&self) -> bool {
        self.outbound_flushed() && self.inbound_drained()
    }

    fn advance_outbound(&mut self, next: Outbound) {
        let valid = next <= self.outbound
            || matches!(
                (self.outbound, next),
                (Outbound::Open, Outbound::Closing)
                    | (Outbound::Closing, Outbound::Flushed)
                    | (Outbound::Flushed, Outbound::Closed)
            );
        debug_assert!(
            valid,
            "outbound close state skipped: {:?} -> {:?}",
            self.outbound, next
        );
        if valid && next > self.outbound {
            self.outbound = next;
        }
    }

    fn advance_inbound(&mut self, next: Inbound) {
        let valid = next <= self.inbound
            || matches!(
                (self.inbound, next),
                (Inbound::Open, Inbound::PeerClosed)
                    | (Inbound::PeerClosed, Inbound::Drained)
                    | (Inbound::Drained, Inbound::EofDelivered)
            );
        debug_assert!(
            valid,
            "inbound close state skipped: {:?} -> {:?}",
            self.inbound, next
        );
        if valid && next > self.inbound {
            self.inbound = next;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUTBOUND: [Outbound; 4] = [
        Outbound::Open,
        Outbound::Closing,
        Outbound::Flushed,
        Outbound::Closed,
    ];
    const INBOUND: [Inbound; 4] = [
        Inbound::Open,
        Inbound::PeerClosed,
        Inbound::Drained,
        Inbound::EofDelivered,
    ];

    #[test]
    fn outbound_transitions_are_monotonic() {
        let mut state = CloseState::new();
        assert_eq!(state.outbound, Outbound::Open);
        assert!(!state.close_requested());

        state.mark_close_requested();
        state.mark_close_requested();
        assert_eq!(state.outbound, Outbound::Closing);

        state.mark_outbound_flushed();
        state.mark_close_requested();
        assert_eq!(state.outbound, Outbound::Flushed);

        state.mark_outbound_closed();
        state.mark_outbound_flushed();
        assert_eq!(state.outbound, Outbound::Closed);
    }

    #[test]
    fn inbound_transitions_are_monotonic() {
        let mut state = CloseState::new();
        assert_eq!(state.inbound, Inbound::Open);
        assert!(!state.peer_closed());

        state.mark_peer_closed();
        state.mark_peer_closed();
        assert_eq!(state.inbound, Inbound::PeerClosed);

        state.mark_drained();
        state.mark_peer_closed();
        assert_eq!(state.inbound, Inbound::Drained);

        state.mark_drained();
        assert_eq!(state.inbound, Inbound::Drained);
        assert!(!state.eof_delivered());

        state.mark_eof_delivered();
        state.mark_drained();
        assert_eq!(state.inbound, Inbound::EofDelivered);
        assert!(state.eof_delivered());
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "inbound close state skipped")]
    fn inbound_steps_cannot_be_skipped() {
        let mut state = CloseState::new();
        state.mark_eof_delivered();
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "outbound close state skipped")]
    fn outbound_steps_cannot_be_skipped() {
        let mut state = CloseState::new();
        state.mark_outbound_closed();
    }

    #[test]
    fn finalize_requires_flushed_and_drained() {
        for (outbound_index, outbound) in OUTBOUND.iter().enumerate() {
            for (inbound_index, inbound) in INBOUND.iter().enumerate() {
                let state = CloseState {
                    outbound: *outbound,
                    inbound: *inbound,
                };
                assert_eq!(
                    state.can_finalize(),
                    outbound_index >= 2 && inbound_index >= 2,
                    "outbound={outbound:?} inbound={inbound:?}"
                );
            }
        }
    }
}
