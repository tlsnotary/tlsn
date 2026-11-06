//! Optional stress mode for the integration harnesses.
//!
//! Disabled by default: with no environment variables set, `repeats()` is 1,
//! delays are zero, and discrete orderings stay canonical. Setting
//! `TLSN_STRESS=1` enables the knobs:
//!
//! - `TLSN_STRESS_REPEATS` — iterations per case (default 1)
//! - `TLSN_STRESS_SEED` — base seed (default 0)
//! - `TLSN_STRESS_MAX_DELAY_MS` — max random delay per hook (default 0)
//!
//! Jitter is scoped per party: each `Party` gets an independent RNG stream
//! seeded from `seed ^ party_salt`, so the client, server, prover, verifier
//! and transport do not share one delay sequence. `Point` names the protocol
//! step a delay is attached to so stress logs can be correlated with a run.

use std::{env, time::Duration};

use tokio::sync::Notify;

pub(crate) struct Stress {
    enabled: bool,
    repeats: usize,
    base_seed: u64,
    max_delay_ms: u64,
}

impl Stress {
    pub(crate) fn from_env() -> Self {
        let enabled = matches!(env::var("TLSN_STRESS").as_deref(), Ok("1") | Ok("true"));
        if !enabled {
            return Self {
                enabled: false,
                repeats: 1,
                base_seed: 0,
                max_delay_ms: 0,
            };
        }

        let repeats = usize::try_from(parse_env("TLSN_STRESS_REPEATS", 1).max(1))
            .expect("TLSN_STRESS_REPEATS is too large");
        let base_seed = parse_env("TLSN_STRESS_SEED", 0);
        let max_delay_ms = parse_env("TLSN_STRESS_MAX_DELAY_MS", 0);

        eprintln!(
            "STRESS enabled: repeats={repeats} seed={base_seed:#x} max_delay_ms={max_delay_ms}"
        );

        Self {
            enabled,
            repeats,
            base_seed,
            max_delay_ms,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn repeats(&self) -> usize {
        self.repeats
    }

    pub(crate) fn plan(&self, iteration: usize) -> Plan {
        let seed = if self.enabled {
            // Distinct, non-zero seed per iteration.
            let seed = self.base_seed ^ iteration as u64;
            if seed == 0 { 1 } else { seed }
        } else {
            0
        };

        if self.enabled {
            eprintln!("STRESS iteration={iteration} seed={seed:#x}");
        }

        Plan {
            enabled: self.enabled,
            iteration,
            seed,
            max_delay_ms: self.max_delay_ms,
            rng: Rng::new(seed),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum Party {
    Client,
    Server,
    Prover,
    Verifier,
    Transport,
}

impl Party {
    fn name(self) -> &'static str {
        match self {
            Party::Client => "client",
            Party::Server => "server",
            Party::Prover => "prover",
            Party::Verifier => "verifier",
            Party::Transport => "transport",
        }
    }

    fn seed_salt(self) -> u64 {
        match self {
            Party::Client => 0xC11E,
            Party::Server => 0x5EED,
            Party::Prover => 0x9A0B,
            Party::Verifier => 0x7E51,
            Party::Transport => 0x7C4F,
        }
    }
}

/// A protocol step that may be delayed in stress mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum Point {
    BeforeWrite,
    BeforeRead,
    BeforeClose,
    BeforeCloseNotify,
    BeforeFin,
    BeforeData,
    BeforeAbort,
    BeforeClientDrop,
}

impl Point {
    fn name(self) -> &'static str {
        match self {
            Point::BeforeWrite => "before_write",
            Point::BeforeRead => "before_read",
            Point::BeforeClose => "before_close",
            Point::BeforeCloseNotify => "before_close_notify",
            Point::BeforeFin => "before_fin",
            Point::BeforeData => "before_data",
            Point::BeforeAbort => "before_abort",
            Point::BeforeClientDrop => "before_client_drop",
        }
    }
}

/// A pair of actions whose relative order is enumerated, not sampled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum RacePoint {
    CloseNotify,
    ClientCloseVsServerFin,
    ClientCloseVsStreamingRecord,
    CommitAccept,
    ProverAbortVsVerifierFinish,
}

impl RacePoint {
    /// Mixed-radix stride so each race point flips independently across
    /// iterations. With two choices per point, N points cover all combinations
    /// over `2^N` iterations.
    #[allow(dead_code)]
    fn stride(self) -> u64 {
        match self {
            RacePoint::CloseNotify => 1,
            RacePoint::ClientCloseVsServerFin => 2,
            RacePoint::ClientCloseVsStreamingRecord => 4,
            RacePoint::CommitAccept => 8,
            RacePoint::ProverAbortVsVerifierFinish => 16,
        }
    }
}

/// A reusable one-shot gate for two competing parties.
///
/// Both parties call [`Gate::wait`]. The chosen first party returns
/// immediately; the other waits until the first party calls [`Gate::open`]
/// after completing its side of the race.
#[allow(dead_code)]
pub(crate) struct Gate {
    first: Party,
    opened: Notify,
}

#[allow(dead_code)]
impl Gate {
    pub(crate) fn new(first: Party) -> Self {
        Self {
            first,
            opened: Notify::new(),
        }
    }

    /// Returns `true` when the caller is the chosen first party.
    pub(crate) async fn wait(&self, party: Party) -> bool {
        if party == self.first {
            true
        } else {
            self.opened.notified().await;
            false
        }
    }

    /// Releases the waiting party. Call once, from the first party.
    pub(crate) fn open(&self) {
        self.opened.notify_one();
    }
}

/// An independent jitter stream for one party.
pub(crate) struct Jitter {
    enabled: bool,
    party: &'static str,
    max_delay_ms: u64,
    rng: Rng,
}

impl Jitter {
    /// Sleeps for a bounded random interval when stress mode is enabled.
    pub(crate) async fn delay(&mut self, point: Point) {
        if !self.enabled || self.max_delay_ms == 0 {
            return;
        }

        let ms = self.rng.range(self.max_delay_ms + 1);
        if ms > 0 {
            eprintln!("STRESS {} delay {}: {ms}ms", self.party, point.name());
            tokio::time::sleep(Duration::from_millis(ms)).await;
        }
    }
}

pub(crate) struct Plan {
    enabled: bool,
    #[allow(dead_code)]
    iteration: usize,
    seed: u64,
    max_delay_ms: u64,
    #[allow(dead_code)]
    rng: Rng,
}

impl Plan {
    #[allow(dead_code)]
    pub(crate) fn seed(&self) -> u64 {
        self.seed
    }

    /// Returns an independent jitter stream for one party.
    ///
    /// Each party gets its own RNG so their delays are uncorrelated while
    /// remaining reproducible from the iteration seed.
    pub(crate) fn jitter(&self, party: Party) -> Jitter {
        let seed = self.seed ^ party.seed_salt();
        Jitter {
            enabled: self.enabled,
            party: party.name(),
            max_delay_ms: self.max_delay_ms,
            rng: Rng::new(seed),
        }
    }

    /// Rotates deterministically through `n` discrete orderings for one race
    /// point.
    ///
    /// Each race point has its own stride, so orderings across different race
    /// points are independent rather than all flipping together. Disabled mode
    /// always returns 0 (the canonical ordering).
    #[allow(dead_code)]
    pub(crate) fn order(&self, point: RacePoint, n: u64) -> u64 {
        if !self.enabled || n == 0 {
            0
        } else {
            (self.iteration as u64 / point.stride()) % n
        }
    }

    /// Driver-side delay for observation/setup only.
    ///
    /// Do not use this for phase-critical transitions: it shares one sequence
    /// across the orchestrator and can advance a phase before a loss step.
    /// Use a party `Jitter` inside the actor instead.
    #[allow(dead_code)]
    pub(crate) async fn delay(&mut self, point: &str) {
        if !self.enabled || self.max_delay_ms == 0 {
            return;
        }

        let ms = self.rng.range(self.max_delay_ms + 1);
        if ms > 0 {
            eprintln!("STRESS delay {point}: {ms}ms");
            tokio::time::sleep(Duration::from_millis(ms)).await;
        }
    }
}

fn parse_env(key: &str, default: u64) -> u64 {
    match env::var(key) {
        Ok(value) => value
            .parse()
            .unwrap_or_else(|_| panic!("{key} must be a non-negative integer, got {value:?}")),
        Err(_) => default,
    }
}

/// Small deterministic RNG so the stress mode has no dependency and is
/// reproducible from the seed.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    fn range(&mut self, upper_exclusive: u64) -> u64 {
        self.next_u64() % upper_exclusive.max(1)
    }
}
