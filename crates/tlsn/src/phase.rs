use std::{fmt, future::Future, sync::Arc};

use tlsn_core::telemetry::{BenchPhase, PhaseEvent, TelemetrySink};
use tracing::{Instrument, trace};

#[derive(Clone)]
pub(crate) struct TelemetryHandle(Arc<dyn TelemetrySink + Send + Sync>);

impl TelemetryHandle {
    pub(crate) fn new(sink: Arc<dyn TelemetrySink + Send + Sync>) -> Self {
        Self(sink)
    }

    pub(crate) fn arc(&self) -> Arc<dyn TelemetrySink + Send + Sync> {
        self.0.clone()
    }

    pub(crate) fn phase_event(&self, phase: BenchPhase, event: PhaseEvent) {
        self.0.phase_event(phase, event);
    }
}

impl fmt::Debug for TelemetryHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TelemetryHandle(..)")
    }
}

pub(crate) struct PhaseGuard {
    phase: BenchPhase,
    telemetry: Option<TelemetryHandle>,
}

impl PhaseGuard {
    fn from_owned(telemetry: Option<TelemetryHandle>, phase: BenchPhase) -> Self {
        trace!("start");

        if let Some(telemetry) = &telemetry {
            telemetry.phase_event(phase, PhaseEvent::Start);
        }

        Self {
            phase,
            telemetry,
        }
    }
}

impl Drop for PhaseGuard {
    fn drop(&mut self) {
        trace!("end");

        if let Some(telemetry) = &self.telemetry {
            telemetry.phase_event(self.phase, PhaseEvent::End);
        }
    }
}

pub(crate) async fn in_phase<F>(
    telemetry: Option<&TelemetryHandle>,
    phase: BenchPhase,
    future: F,
) -> F::Output
where
    F: Future,
{
    let telemetry = telemetry.cloned();

    async move {
        let _phase = PhaseGuard::from_owned(telemetry, phase);
        future.await
    }
    .instrument(tracing::debug_span!("bench_phase", phase = phase.as_str()))
    .await
}
