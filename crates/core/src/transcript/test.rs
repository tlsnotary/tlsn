//! Exhaustive test harness for transcript union operations.
//!
//! It enumerates every subset of a small universe and checks an operation
//! against a naive reference implementation on full-length buffers.

use rangeset::set::RangeSet;

use super::{Direction, PartialTranscript, Subsequence, merge_disjoint, subset_bytes};

/// The size of the universe used by the exhaustive harness.
pub(crate) const TEST_DOMAIN_SIZE: usize = 6;

/// A set of positions in `0..domain`, stored as a bitmask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Set(u64);

impl Set {
    /// Returns whether `pos` is in the set.
    pub(crate) fn contains(self, pos: usize) -> bool {
        self.0 & (1u64 << pos) != 0
    }

    /// Returns the union of two sets.
    pub(crate) fn union(self, other: Set) -> Set {
        Set(self.0 | other.0)
    }

    /// Returns the set as a [`RangeSet`].
    pub(crate) fn to_rangeset(self) -> RangeSet<usize> {
        let mut ranges = Vec::new();
        let mut start = None;

        for pos in 0..64 {
            if self.contains(pos) {
                start.get_or_insert(pos);
            } else if let Some(start) = start.take() {
                ranges.push(start..pos);
            }
        }

        RangeSet::new_from_slice(&ranges)
    }
}

/// The universe of all subsets of `0..domain`.
pub(crate) struct Universe {
    domain: usize,
}

impl Universe {
    /// Creates a new universe of the given size.
    pub(crate) fn new(domain: usize) -> Self {
        Self { domain }
    }

    /// Iterates over every subset of the universe, in bitmask order.
    pub(crate) fn iter_sets(&self) -> impl Iterator<Item = Set> + '_ {
        (0..1u64 << self.domain).map(Set)
    }
}

/// Returns the authenticated bytes of `set`, using `byte` for each position.
fn authed_bytes(set: Set, byte: fn(usize) -> u8) -> Vec<u8> {
    set.to_rangeset()
        .iter()
        .flat_map(|range| range.map(byte))
        .collect()
}

/// Builds a transcript whose `Sent` direction authenticates `set`, with each
/// authenticated byte supplied by `byte`.
fn transcript(set: Set, byte: fn(usize) -> u8, domain: usize) -> PartialTranscript {
    PartialTranscript {
        sent_authed: authed_bytes(set, byte),
        received_authed: Vec::new(),
        sent_idx: set.to_rangeset(),
        recv_idx: RangeSet::default(),
        sent_total: domain,
        recv_total: 0,
    }
}

/// Distinct byte functions per source, so that precedence on overlap is
/// observable.
fn self_byte(pos: usize) -> u8 {
    0x10 + pos as u8
}

fn other_byte(pos: usize) -> u8 {
    0x20 + pos as u8
}

fn seq_byte(pos: usize) -> u8 {
    0x30 + pos as u8
}

/// Asserts that `union_transcript` matches a naive reference for every pair of
/// sets of the universe.
pub(crate) fn assert_union_transcript(domain: usize) {
    let universe = Universe::new(domain);

    for a in universe.iter_sets() {
        for b in universe.iter_sets() {
            let mut actual = transcript(a, self_byte, domain);
            actual.union_transcript(&transcript(b, other_byte, domain));

            // `self` wins on overlap; `other` fills the rest.
            let mut expected = vec![0u8; domain];
            for (pos, slot) in expected.iter_mut().enumerate() {
                if a.contains(pos) {
                    *slot = self_byte(pos);
                } else if b.contains(pos) {
                    *slot = other_byte(pos);
                }
            }

            assert_eq!(
                actual.sent_authed(),
                &a.union(b).to_rangeset(),
                "a={a:?} b={b:?}"
            );
            assert_eq!(
                actual.sent_unsafe(domain).unwrap(),
                expected,
                "a={a:?} b={b:?}"
            );
        }
    }
}

/// Asserts that `union_subsequence` matches a naive reference for every pair of
/// sets of the universe.
pub(crate) fn assert_union_subsequence(domain: usize) {
    let universe = Universe::new(domain);

    for base in universe.iter_sets() {
        for sub in universe.iter_sets() {
            let mut actual = transcript(base, self_byte, domain);

            let sub_idx = sub.to_rangeset();
            let sub_data = sub_idx
                .iter()
                .flat_map(|range| range.map(seq_byte))
                .collect();
            let subsequence = Subsequence::new(sub_idx, sub_data).unwrap();
            actual.union_subsequence(Direction::Sent, &subsequence);

            // The subsequence wins on overlap; the base fills the rest.
            let mut expected = vec![0u8; domain];
            for (pos, slot) in expected.iter_mut().enumerate() {
                if sub.contains(pos) {
                    *slot = seq_byte(pos);
                } else if base.contains(pos) {
                    *slot = self_byte(pos);
                }
            }

            assert_eq!(
                actual.sent_authed(),
                &base.union(sub).to_rangeset(),
                "base={base:?} sub={sub:?}"
            );
            assert_eq!(
                actual.sent_unsafe(domain).unwrap(),
                expected,
                "base={base:?} sub={sub:?}"
            );
        }
    }
}

/// Asserts that `materialize_range` matches the corresponding slice of the
/// naively materialized buffer, for every set and every range of the universe.
pub(crate) fn assert_materialize_range(domain: usize) {
    let universe = Universe::new(domain);

    for set in universe.iter_sets() {
        let transcript = transcript(set, self_byte, domain);

        // Reference: the full buffer, zero-filled outside the authenticated
        // set.
        let expected: Vec<u8> = (0..domain)
            .map(|pos| if set.contains(pos) { self_byte(pos) } else { 0 })
            .collect();

        for start in 0..=domain {
            for end in start..=domain {
                let actual = transcript.materialize_range(Direction::Sent, &(start..end));
                assert_eq!(
                    actual.as_slice(),
                    &expected[start..end],
                    "set={set:?} range={start}..{end}"
                );
            }
        }
    }
}

/// Asserts that `locate` returns the authenticated bytes exactly when a range
/// is fully authenticated, for every set and every range of the universe.
pub(crate) fn assert_locate(domain: usize) {
    let universe = Universe::new(domain);

    for set in universe.iter_sets() {
        let transcript = transcript(set, self_byte, domain);

        let expected: Vec<u8> = (0..domain)
            .map(|pos| if set.contains(pos) { self_byte(pos) } else { 0 })
            .collect();

        for start in 0..domain {
            for end in (start + 1)..=domain {
                let located = transcript.locate(Direction::Sent, &(start..end));

                if (start..end).all(|pos| set.contains(pos)) {
                    assert_eq!(
                        located,
                        Some(&expected[start..end]),
                        "set={set:?} range={start}..{end}"
                    );
                } else {
                    assert_eq!(located, None, "set={set:?} range={start}..{end}");
                }
            }
        }
    }
}

/// Asserts that `subset_bytes` matches a naive extraction for every pair of
/// sets where the second is a subset of the first.
pub(crate) fn assert_subset_bytes(domain: usize) {
    let universe = Universe::new(domain);

    for idx in universe.iter_sets() {
        let idx_ranges = idx.to_rangeset();
        let bytes = authed_bytes(idx, self_byte);

        for sub in universe.iter_sets() {
            // `sub` must be a subset of `idx`.
            if sub.0 & !idx.0 != 0 {
                continue;
            }

            let actual = subset_bytes(&idx_ranges, &bytes, &sub.to_rangeset());

            let expected: Vec<u8> = (0..domain)
                .filter(|pos| sub.contains(*pos))
                .map(self_byte)
                .collect();

            assert_eq!(actual, expected, "idx={idx:?} sub={sub:?}");
        }
    }
}

/// Asserts that `merge_disjoint` matches a naive merge for every pair of
/// disjoint sets.
pub(crate) fn assert_merge_disjoint(domain: usize) {
    let universe = Universe::new(domain);

    for a in universe.iter_sets() {
        for b in universe.iter_sets() {
            // The inputs must be disjoint.
            if a.0 & b.0 != 0 {
                continue;
            }

            let a_bytes = authed_bytes(a, self_byte);
            let b_bytes = authed_bytes(b, other_byte);

            let (idx, bytes) =
                merge_disjoint(&a.to_rangeset(), &a_bytes, &b.to_rangeset(), &b_bytes);

            let expected: Vec<u8> = (0..domain)
                .filter_map(|pos| {
                    if a.contains(pos) {
                        Some(self_byte(pos))
                    } else if b.contains(pos) {
                        Some(other_byte(pos))
                    } else {
                        None
                    }
                })
                .collect();

            assert_eq!(idx, a.union(b).to_rangeset(), "a={a:?} b={b:?}");
            assert_eq!(bytes, expected, "a={a:?} b={b:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_union_transcript_exhaustive() {
        assert_union_transcript(TEST_DOMAIN_SIZE);
    }

    #[test]
    fn test_union_subsequence_exhaustive() {
        assert_union_subsequence(TEST_DOMAIN_SIZE);
    }

    #[test]
    fn test_materialize_range_exhaustive() {
        assert_materialize_range(TEST_DOMAIN_SIZE);
    }

    #[test]
    fn test_locate_exhaustive() {
        assert_locate(TEST_DOMAIN_SIZE);
    }

    #[test]
    fn test_subset_bytes_exhaustive() {
        assert_subset_bytes(TEST_DOMAIN_SIZE);
    }

    #[test]
    fn test_merge_disjoint_exhaustive() {
        assert_merge_disjoint(TEST_DOMAIN_SIZE);
    }
}
