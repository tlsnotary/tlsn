//! Transcript reference storage.

use std::ops::Range;

use mpz_memory_core::{FromRaw, Slice, ToRaw, Vector, binary::U8};
use rangeset::{Difference, Disjoint, RangeSet, Subset, UnionMut};
use tlsn_core::transcript::Direction;

/// References to the application plaintext in the transcript.
#[derive(Debug, Clone)]
pub(crate) struct TranscriptRefs {
    sent: RefStorage,
    recv: RefStorage,
}

impl TranscriptRefs {
    /// Creates a new instance.
    ///
    /// # Arguments
    ///
    /// `sent_max_len` - The maximum length of the sent transcript in bytes.
    /// `recv_max_len` - The maximum length of the received transcript in bytes.
    pub(crate) fn new(sent_max_len: usize, recv_max_len: usize) -> Self {
        let sent = RefStorage::new(sent_max_len);
        let recv = RefStorage::new(recv_max_len);

        Self { sent, recv }
    }

    /// Adds new references to the transcript refs.
    ///
    /// New transcript references are only added if none of them are already
    /// present.
    ///
    /// # Arguments
    ///
    /// * `direction` - The direction of the transcript.
    /// * `index` - The index of the transcript references.
    /// * `refs` - The new transcript refs.
    pub(crate) fn add(&mut self, direction: Direction, index: &Range<usize>, refs: Vector<U8>) {
        match direction {
            Direction::Sent => self.sent.add(index, refs),
            Direction::Received => self.recv.add(index, refs),
        }
    }

    /// Marks references of the transcript as decoded.
    ///
    /// # Arguments
    ///
    /// * `direction` - The direction of the transcript.
    /// * `index` - The index of the transcript references.
    pub(crate) fn mark_decoded(&mut self, direction: Direction, index: &RangeSet<usize>) {
        match direction {
            Direction::Sent => self.sent.mark_decoded(index),
            Direction::Received => self.recv.mark_decoded(index),
        }
    }

    /// Returns plaintext references for some index.
    ///
    /// Queries that cannot or only partially be satisfied will return an empty
    /// vector.
    ///
    /// # Arguments
    ///
    /// * `direction` - The direction of the transcript.
    /// * `index` - The index of the transcript references.
    pub(crate) fn get(&self, direction: Direction, index: &RangeSet<usize>) -> Vec<Vector<U8>> {
        match direction {
            Direction::Sent => self.sent.get(index),
            Direction::Received => self.recv.get(index),
        }
    }

    /// Computes the subset of `index` which is missing.
    ///
    /// # Arguments
    ///
    /// * `direction` - The direction of the transcript.
    /// * `index` - The index of the transcript references.
    pub(crate) fn compute_missing(
        &self,
        direction: Direction,
        index: &RangeSet<usize>,
    ) -> RangeSet<usize> {
        match direction {
            Direction::Sent => self.sent.compute_missing(index),
            Direction::Received => self.recv.compute_missing(index),
        }
    }

    /// Returns the maximum length of the transcript.
    ///
    /// # Arguments
    ///
    /// * `direction` - The direction of the transcript.
    pub(crate) fn max_len(&self, direction: Direction) -> usize {
        match direction {
            Direction::Sent => self.sent.max_len(),
            Direction::Received => self.recv.max_len(),
        }
    }

    /// Returns the decoded ranges of the transcript.
    ///
    /// # Arguments
    ///
    /// * `direction` - The direction of the transcript.
    pub(crate) fn decoded(&self, direction: Direction) -> RangeSet<usize> {
        match direction {
            Direction::Sent => self.sent.decoded(),
            Direction::Received => self.recv.decoded(),
        }
    }

    /// Returns the set ranges of the transcript.
    ///
    /// # Arguments
    ///
    /// * `direction` - The direction of the transcript.
    #[cfg(test)]
    pub(crate) fn index(&self, direction: Direction) -> RangeSet<usize> {
        match direction {
            Direction::Sent => self.sent.index(),
            Direction::Received => self.recv.index(),
        }
    }
}

/// Inner storage for transcript references.
///
/// Saves transcript references by maintaining an `index` and an `offset`. The
/// offset translates from `index` to some memory location and contains
/// information about possibly non-contigious memory locations. The storage is
/// bit-addressed but the API works with ranges over bytes.
#[derive(Debug, Clone)]
struct RefStorage {
    index: RangeSet<usize>,
    decoded: RangeSet<usize>,
    offset: Vec<isize>,
    max_len: usize,
}

impl RefStorage {
    fn new(max_len: usize) -> Self {
        Self {
            index: RangeSet::default(),
            decoded: RangeSet::default(),
            offset: Vec::default(),
            max_len: 8 * max_len,
        }
    }

    fn add(&mut self, index: &Range<usize>, data: Vector<U8>) {
        assert!(
            index.start < index.end,
            "Range should be valid for adding to reference storage"
        );
        assert_eq!(
            index.len(),
            data.len(),
            "Provided index and vm references should have the same length"
        );
        let bit_index = 8 * index.start..8 * index.end;

        assert!(
            bit_index.is_disjoint(&self.index),
            "Parts of the provided index have already been computed"
        );
        assert!(
            bit_index.end <= self.max_len,
            "Provided index should be smaller than max_len"
        );

        if bit_index.end > self.offset.len() {
            self.offset.resize(bit_index.end, 0);
        }

        let mem_address = data.to_raw().ptr().as_usize() as isize;
        let offset = mem_address - bit_index.start as isize;

        self.index.union_mut(&bit_index);
        self.offset[bit_index].fill(offset);
    }

    fn mark_decoded(&mut self, index: &RangeSet<usize>) {
        let bit_index = to_bit_index(index);
        self.decoded.union_mut(&bit_index);
    }

    fn get(&self, index: &RangeSet<usize>) -> Vec<Vector<U8>> {
        let bit_index = to_bit_index(index);

        if bit_index.is_empty() || !bit_index.is_subset(&self.index) {
            return Vec::new();
        }

        // Partition rangeset into ranges mapping to possibly disjunct memory locations.
        //
        // If the offset changes during iteration of a single range, it means that the
        // backing memory is non-contigious and we need to split that range.
        let mut transcript_refs = Vec::new();

        for idx in bit_index.iter_ranges() {
            let mut start = idx.start;
            let mut end = idx.start;
            let mut offset = self.offset[start];

            for k in idx {
                let next_offset = self.offset[k];
                if next_offset == offset {
                    end += 1;
                    continue;
                }

                let len = end - start;

                let ptr = (start as isize + offset) as usize;
                let mem_ref = Slice::from_range_unchecked(ptr..ptr + len);
                transcript_refs.push(Vector::from_raw(mem_ref));

                start = k;
                end = k + 1;
                offset = next_offset;
            }
            let len = end - start;

            let ptr = (start as isize + offset) as usize;
            let mem_ref = Slice::from_range_unchecked(ptr..ptr + len);

            transcript_refs.push(Vector::from_raw(mem_ref));
        }

        transcript_refs
    }

    fn compute_missing(&self, index: &RangeSet<usize>) -> RangeSet<usize> {
        let byte_index = to_byte_index(&self.index);
        index.difference(&byte_index)
    }

    fn decoded(&self) -> RangeSet<usize> {
        to_byte_index(&self.decoded)
    }

    fn max_len(&self) -> usize {
        self.max_len / 8
    }

    #[cfg(test)]
    fn index(&self) -> RangeSet<usize> {
        to_byte_index(&self.index)
    }
}

fn to_bit_index(index: &RangeSet<usize>) -> RangeSet<usize> {
    let mut bit_index = RangeSet::default();

    for r in index.iter_ranges() {
        bit_index.union_mut(&(8 * r.start..8 * r.end));
    }
    bit_index
}

fn to_byte_index(index: &RangeSet<usize>) -> RangeSet<usize> {
    let mut byte_index = RangeSet::default();

    for r in index.iter_ranges() {
        let start = r.start;
        let end = r.end;

        assert!(
            start.trailing_zeros() >= 3,
            "start range should be divisible by 8"
        );
        assert!(
            end.trailing_zeros() >= 3,
            "end range should be divisible by 8"
        );

        let start = start >> 3;
        let end = end >> 3;

        byte_index.union_mut(&(start..end));
    }

    byte_index
}

#[cfg(test)]
mod tests {
    use crate::commit::transcript::RefStorage;
    use mpz_memory_core::{FromRaw, Slice, ToRaw, Vector, binary::U8};
    use rangeset::{RangeSet, UnionMut};
    use rstest::{fixture, rstest};
    use std::ops::Range;

    #[rstest]
    fn test_storage_add(
        max_len: usize,
        ranges: [Range<usize>; 6],
        offsets: [isize; 6],
        storage: RefStorage,
    ) {
        let bit_ranges: Vec<Range<usize>> = ranges.iter().map(|r| 8 * r.start..8 * r.end).collect();
        let bit_offsets: Vec<isize> = offsets.iter().map(|o| 8 * o).collect();

        let mut expected_index: RangeSet<usize> = RangeSet::default();

        expected_index.union_mut(&bit_ranges[0]);
        expected_index.union_mut(&bit_ranges[1]);

        expected_index.union_mut(&bit_ranges[2]);
        expected_index.union_mut(&bit_ranges[3]);

        expected_index.union_mut(&bit_ranges[4]);
        expected_index.union_mut(&bit_ranges[5]);
        assert_eq!(storage.index, expected_index);

        let end = expected_index.end().unwrap();
        let mut expected_offset = vec![0_isize; end];

        expected_offset[bit_ranges[0].clone()].fill(bit_offsets[0]);
        expected_offset[bit_ranges[1].clone()].fill(bit_offsets[1]);

        expected_offset[bit_ranges[2].clone()].fill(bit_offsets[2]);
        expected_offset[bit_ranges[3].clone()].fill(bit_offsets[3]);

        expected_offset[bit_ranges[4].clone()].fill(bit_offsets[4]);
        expected_offset[bit_ranges[5].clone()].fill(bit_offsets[5]);

        assert_eq!(storage.offset, expected_offset);

        assert_eq!(storage.decoded, RangeSet::default());
        assert_eq!(storage.max_len, 8 * max_len);
    }

    #[rstest]
    fn test_storage_get(ranges: [Range<usize>; 6], offsets: [isize; 6], storage: RefStorage) {
        let mut index = RangeSet::default();
        ranges.iter().for_each(|r| index.union_mut(r));

        let data = storage.get(&index);

        let mut data_recovered = Vec::new();
        for (r, o) in ranges.iter().zip(offsets) {
            data_recovered.push(vec(r.start as isize + o..r.end as isize + o));
        }

        // Merge possibly adjacent vectors.
        //
        // Two vectors are adjacent if
        //
        // - vectors are adjacent in memory.
        // - transcript ranges of those vectors are adjacent, too.
        let mut range_iter = ranges.iter();
        let mut vec_iter = data_recovered.iter();
        let mut data_expected = Vec::new();

        let mut current_vec = vec_iter.next().unwrap().to_raw().to_range();
        let mut current_range = range_iter.next().unwrap();

        for (r, v) in range_iter.zip(vec_iter) {
            let v_range = v.to_raw().to_range();
            let start = v_range.start;
            let end = v_range.end;

            if current_vec.end == start && current_range.end == r.start {
                current_vec.end = end;
            } else {
                let v = Vector::<U8>::from_raw(Slice::from_range_unchecked(current_vec));
                data_expected.push(v);
                current_vec = start..end;
                current_range = r;
            }
        }
        let v = Vector::<U8>::from_raw(Slice::from_range_unchecked(current_vec));
        data_expected.push(v);
        assert_eq!(data, data_expected);
    }

    #[rstest]
    fn test_storage_compute_missing(storage: RefStorage) {
        let mut range = RangeSet::default();
        range.union_mut(&(6..12));
        range.union_mut(&(18..21));
        range.union_mut(&(22..25));
        range.union_mut(&(50..60));

        let missing = storage.compute_missing(&range);

        let mut missing_expected = RangeSet::default();
        missing_expected.union_mut(&(8..12));
        missing_expected.union_mut(&(20..21));
        missing_expected.union_mut(&(50..60));

        assert_eq!(missing, missing_expected);
    }

    #[rstest]
    fn test_mark_decoded(mut storage: RefStorage) {
        let mut range = RangeSet::default();

        range.union_mut(&(14..17));
        range.union_mut(&(30..37));

        storage.mark_decoded(&range);
        let decoded = storage.decoded();

        assert_eq!(range, decoded);
    }

    #[fixture]
    fn max_len() -> usize {
        1000
    }

    #[fixture]
    fn ranges() -> [Range<usize>; 6] {
        let r1 = 0..5;
        let r2 = 5..8;
        let r3 = 12..20;
        let r4 = 22..26;
        let r5 = 30..35;
        let r6 = 35..38;

        [r1, r2, r3, r4, r5, r6]
    }

    #[fixture]
    fn offsets() -> [isize; 6] {
        [7, 9, 20, 18, 30, 30]
    }

    // expected memory ranges: 8 * ranges + 8 * offsets
    // 1. 56..96    do not merge with next one, because not adjacent in memory
    // 2. 112..136
    // 3. 256..320  do not merge with next one, adjacent in memory, but the ranges
    //    itself are not
    // 4. 320..352
    // 5. 480..520  merge with next one
    // 6  520..544
    //
    //
    // 1. 56..96,   length: 5
    // 2. 112..136, length: 3
    // 3. 256..320, length: 8
    // 4. 320..352, length: 4
    // 5. 480..544, length: 8
    #[fixture]
    fn storage(max_len: usize, ranges: [Range<usize>; 6], offsets: [isize; 6]) -> RefStorage {
        let [r1, r2, r3, r4, r5, r6] = ranges;
        let [o1, o2, o3, o4, o5, o6] = offsets;

        let mut storage = RefStorage::new(max_len);
        storage.add(&r1, vec(r1.start as isize + o1..r1.end as isize + o1));
        storage.add(&r2, vec(r2.start as isize + o2..r2.end as isize + o2));

        storage.add(&r3, vec(r3.start as isize + o3..r3.end as isize + o3));
        storage.add(&r4, vec(r4.start as isize + o4..r4.end as isize + o4));

        storage.add(&r5, vec(r5.start as isize + o5..r5.end as isize + o5));
        storage.add(&r6, vec(r6.start as isize + o6..r6.end as isize + o6));

        storage
    }

    fn vec(range: Range<isize>) -> Vector<U8> {
        let range = 8 * range.start as usize..8 * range.end as usize;
        Vector::from_raw(Slice::from_range_unchecked(range))
    }
}
