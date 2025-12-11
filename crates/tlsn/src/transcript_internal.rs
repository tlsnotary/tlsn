pub(crate) mod auth;
pub(crate) mod commit;
pub(crate) mod predicate;

use mpz_memory_core::{Vector, binary::U8};

use crate::map::RangeMap;

/// Maps transcript ranges to VM references.
pub(crate) type ReferenceMap = RangeMap<Vector<U8>>;

/// References to the application plaintext in the transcript.
#[derive(Debug, Default, Clone)]
pub(crate) struct TranscriptRefs {
    pub(crate) sent: ReferenceMap,
    pub(crate) recv: ReferenceMap,
}
