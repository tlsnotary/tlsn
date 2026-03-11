use std::{
    collections::HashMap,
    sync::{Mutex, PoisonError},
    time::Duration,
};

use harness_core::bench::PhaseMetrics;
use tlsn::telemetry::{BenchPhase, PhaseEvent, TelemetrySink};
use web_time::Instant;

use crate::bench::io::{MeterSnapshot, MeterStats};

#[derive(Clone)]
struct PhaseSnapshot {
    started_at: Instant,
    meter: MeterSnapshot,
}

#[derive(Clone, Copy, Default)]
struct PhaseAggregate {
    count: u64,
    time_ns: u64,
    uploaded_bytes: u64,
    downloaded_bytes: u64,
    io_wait_read_ns: u64,
    io_wait_write_ns: u64,
}

#[derive(Default)]
struct State {
    active: HashMap<BenchPhase, Vec<PhaseSnapshot>>,
    aggregates: HashMap<BenchPhase, PhaseAggregate>,
}

pub(crate) struct BenchmarkTelemetry {
    meter: MeterStats,
    state: Mutex<State>,
}

impl BenchmarkTelemetry {
    pub(crate) fn new(meter: MeterStats) -> Self {
        Self {
            meter,
            state: Mutex::new(State::default()),
        }
    }

    pub(crate) fn phase_metrics(&self) -> PhaseMetrics {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let mut metrics = PhaseMetrics::default();

        for phase in BenchPhase::ALL {
            let aggregate = state.aggregates.get(&phase).copied().unwrap_or_default();
            apply_phase_metrics(&mut metrics, phase, aggregate);
        }

        metrics
    }
}

impl TelemetrySink for BenchmarkTelemetry {
    fn phase_event(&self, phase: BenchPhase, event: PhaseEvent) {
        let meter = self.meter.snapshot();
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);

        match event {
            PhaseEvent::Start => {
                state
                    .active
                    .entry(phase)
                    .or_default()
                    .push(PhaseSnapshot {
                        started_at: now,
                        meter,
                    });
            }
            PhaseEvent::End => {
                let Some(snapshot) = state.active.get_mut(&phase).and_then(Vec::pop) else {
                    return;
                };

                let aggregate = state.aggregates.entry(phase).or_default();
                aggregate.count += 1;
                aggregate.time_ns += duration_to_ns(now.duration_since(snapshot.started_at));
                aggregate.uploaded_bytes += meter.sent.saturating_sub(snapshot.meter.sent);
                aggregate.downloaded_bytes += meter.recv.saturating_sub(snapshot.meter.recv);
                aggregate.io_wait_read_ns += meter
                    .read_wait_ns
                    .saturating_sub(snapshot.meter.read_wait_ns);
                aggregate.io_wait_write_ns += meter
                    .write_wait_ns
                    .saturating_sub(snapshot.meter.write_wait_ns);
            }
        }
    }
}

fn duration_to_ns(duration: Duration) -> u64 {
    duration.as_nanos().min(u64::MAX as u128) as u64
}

fn ns_to_ms(duration_ns: u64) -> u64 {
    duration_ns / 1_000_000
}

fn apply_phase_metrics(metrics: &mut PhaseMetrics, phase: BenchPhase, aggregate: PhaseAggregate) {
    match phase {
        BenchPhase::PreprocessSetup => {
            metrics.phase_preprocess_setup_count = aggregate.count;
            metrics.phase_preprocess_setup_time_ms = ns_to_ms(aggregate.time_ns);
            metrics.phase_preprocess_setup_uploaded_bytes = aggregate.uploaded_bytes;
            metrics.phase_preprocess_setup_downloaded_bytes = aggregate.downloaded_bytes;
            metrics.phase_preprocess_setup_io_wait_read_ms = ns_to_ms(aggregate.io_wait_read_ns);
            metrics.phase_preprocess_setup_io_wait_write_ms = ns_to_ms(aggregate.io_wait_write_ns);
        }
        BenchPhase::HandshakeKeOnline => {
            metrics.phase_handshake_ke_online_count = aggregate.count;
            metrics.phase_handshake_ke_online_time_ms = ns_to_ms(aggregate.time_ns);
            metrics.phase_handshake_ke_online_uploaded_bytes = aggregate.uploaded_bytes;
            metrics.phase_handshake_ke_online_downloaded_bytes = aggregate.downloaded_bytes;
            metrics.phase_handshake_ke_online_io_wait_read_ms = ns_to_ms(aggregate.io_wait_read_ns);
            metrics.phase_handshake_ke_online_io_wait_write_ms =
                ns_to_ms(aggregate.io_wait_write_ns);
        }
        BenchPhase::HandshakePrfSessionKeys => {
            metrics.phase_handshake_prf_session_keys_count = aggregate.count;
            metrics.phase_handshake_prf_session_keys_time_ms = ns_to_ms(aggregate.time_ns);
            metrics.phase_handshake_prf_session_keys_uploaded_bytes = aggregate.uploaded_bytes;
            metrics.phase_handshake_prf_session_keys_downloaded_bytes = aggregate.downloaded_bytes;
            metrics.phase_handshake_prf_session_keys_io_wait_read_ms =
                ns_to_ms(aggregate.io_wait_read_ns);
            metrics.phase_handshake_prf_session_keys_io_wait_write_ms =
                ns_to_ms(aggregate.io_wait_write_ns);
        }
        BenchPhase::HandshakeRecordSetup => {
            metrics.phase_handshake_record_setup_count = aggregate.count;
            metrics.phase_handshake_record_setup_time_ms = ns_to_ms(aggregate.time_ns);
            metrics.phase_handshake_record_setup_uploaded_bytes = aggregate.uploaded_bytes;
            metrics.phase_handshake_record_setup_downloaded_bytes = aggregate.downloaded_bytes;
            metrics.phase_handshake_record_setup_io_wait_read_ms =
                ns_to_ms(aggregate.io_wait_read_ns);
            metrics.phase_handshake_record_setup_io_wait_write_ms =
                ns_to_ms(aggregate.io_wait_write_ns);
        }
        BenchPhase::HandshakePrfServerFinished => {
            metrics.phase_handshake_prf_server_finished_count = aggregate.count;
            metrics.phase_handshake_prf_server_finished_time_ms = ns_to_ms(aggregate.time_ns);
            metrics.phase_handshake_prf_server_finished_uploaded_bytes = aggregate.uploaded_bytes;
            metrics.phase_handshake_prf_server_finished_downloaded_bytes = aggregate.downloaded_bytes;
            metrics.phase_handshake_prf_server_finished_io_wait_read_ms =
                ns_to_ms(aggregate.io_wait_read_ns);
            metrics.phase_handshake_prf_server_finished_io_wait_write_ms =
                ns_to_ms(aggregate.io_wait_write_ns);
        }
        BenchPhase::HandshakePrfClientFinished => {
            metrics.phase_handshake_prf_client_finished_count = aggregate.count;
            metrics.phase_handshake_prf_client_finished_time_ms = ns_to_ms(aggregate.time_ns);
            metrics.phase_handshake_prf_client_finished_uploaded_bytes = aggregate.uploaded_bytes;
            metrics.phase_handshake_prf_client_finished_downloaded_bytes = aggregate.downloaded_bytes;
            metrics.phase_handshake_prf_client_finished_io_wait_read_ms =
                ns_to_ms(aggregate.io_wait_read_ns);
            metrics.phase_handshake_prf_client_finished_io_wait_write_ms =
                ns_to_ms(aggregate.io_wait_write_ns);
        }
        BenchPhase::RecordLayerFlush => {
            metrics.phase_record_layer_flush_count = aggregate.count;
            metrics.phase_record_layer_flush_time_ms = ns_to_ms(aggregate.time_ns);
            metrics.phase_record_layer_flush_uploaded_bytes = aggregate.uploaded_bytes;
            metrics.phase_record_layer_flush_downloaded_bytes = aggregate.downloaded_bytes;
            metrics.phase_record_layer_flush_io_wait_read_ms = ns_to_ms(aggregate.io_wait_read_ns);
            metrics.phase_record_layer_flush_io_wait_write_ms =
                ns_to_ms(aggregate.io_wait_write_ns);
        }
        BenchPhase::FinalizeTlsAuth => {
            metrics.phase_finalize_tls_auth_count = aggregate.count;
            metrics.phase_finalize_tls_auth_time_ms = ns_to_ms(aggregate.time_ns);
            metrics.phase_finalize_tls_auth_uploaded_bytes = aggregate.uploaded_bytes;
            metrics.phase_finalize_tls_auth_downloaded_bytes = aggregate.downloaded_bytes;
            metrics.phase_finalize_tls_auth_io_wait_read_ms = ns_to_ms(aggregate.io_wait_read_ns);
            metrics.phase_finalize_tls_auth_io_wait_write_ms =
                ns_to_ms(aggregate.io_wait_write_ns);
        }
        BenchPhase::ProveTranscript => {
            metrics.phase_prove_transcript_count = aggregate.count;
            metrics.phase_prove_transcript_time_ms = ns_to_ms(aggregate.time_ns);
            metrics.phase_prove_transcript_uploaded_bytes = aggregate.uploaded_bytes;
            metrics.phase_prove_transcript_downloaded_bytes = aggregate.downloaded_bytes;
            metrics.phase_prove_transcript_io_wait_read_ms = ns_to_ms(aggregate.io_wait_read_ns);
            metrics.phase_prove_transcript_io_wait_write_ms =
                ns_to_ms(aggregate.io_wait_write_ns);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{io, pin::Pin, sync::Arc, task::Poll, thread, time::Duration};

    use futures::{AsyncRead, AsyncWrite};

    use super::*;
    use crate::bench::Meter;

    #[derive(Default)]
    struct NoopIo;

    impl AsyncWrite for NoopIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(0))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for NoopIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(0))
        }
    }

    struct TestGuard {
        telemetry: Arc<BenchmarkTelemetry>,
        phase: BenchPhase,
    }

    impl TestGuard {
        fn new(telemetry: Arc<BenchmarkTelemetry>, phase: BenchPhase) -> Self {
            telemetry.phase_event(phase, PhaseEvent::Start);
            Self { telemetry, phase }
        }
    }

    impl Drop for TestGuard {
        fn drop(&mut self) {
            self.telemetry.phase_event(self.phase, PhaseEvent::End);
        }
    }

    #[test]
    fn benchmark_telemetry_accumulates_repeated_entries() {
        let telemetry = Arc::new(BenchmarkTelemetry::new(Meter::new(NoopIo).stats()));

        {
            let _guard = TestGuard::new(telemetry.clone(), BenchPhase::RecordLayerFlush);
            thread::sleep(Duration::from_millis(1));
        }

        {
            let _guard = TestGuard::new(telemetry.clone(), BenchPhase::RecordLayerFlush);
            thread::sleep(Duration::from_millis(1));
        }

        let metrics = telemetry.phase_metrics();
        assert_eq!(metrics.phase_record_layer_flush_count, 2);
        assert!(metrics.phase_record_layer_flush_time_ms > 0);
    }

    #[test]
    fn benchmark_telemetry_keeps_phases_isolated() {
        let telemetry = Arc::new(BenchmarkTelemetry::new(Meter::new(NoopIo).stats()));

        {
            let _guard = TestGuard::new(telemetry.clone(), BenchPhase::PreprocessSetup);
            thread::sleep(Duration::from_millis(1));
        }

        {
            let _guard = TestGuard::new(telemetry.clone(), BenchPhase::ProveTranscript);
            thread::sleep(Duration::from_millis(1));
        }

        let metrics = telemetry.phase_metrics();
        assert_eq!(metrics.phase_preprocess_setup_count, 1);
        assert_eq!(metrics.phase_prove_transcript_count, 1);
        assert_eq!(metrics.phase_record_layer_flush_count, 0);
    }

    #[test]
    fn benchmark_telemetry_records_end_on_error_drop() {
        fn fail_with_guard(telemetry: Arc<BenchmarkTelemetry>) -> Result<(), &'static str> {
            let _guard = TestGuard::new(telemetry, BenchPhase::FinalizeTlsAuth);
            Err("boom")
        }

        let telemetry = Arc::new(BenchmarkTelemetry::new(Meter::new(NoopIo).stats()));
        assert!(fail_with_guard(telemetry.clone()).is_err());

        let metrics = telemetry.phase_metrics();
        assert_eq!(metrics.phase_finalize_tls_auth_count, 1);
    }
}
