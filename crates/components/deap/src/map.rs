use std::ops::Range;

use mpz_vm_core::{memory::Slice, VmError};
use rangeset::Subset;

/// A mapping between the memories of the MPC and ZK VMs.
#[derive(Debug, Default)]
pub(crate) struct MemoryMap {
    mpc: Vec<Range<usize>>,
    zk: Vec<Range<usize>>,
}

impl MemoryMap {
    /// Inserts a new allocation into the map.
    ///
    /// # Panics
    ///
    /// - If the slices are not inserted in the order they are allocated.
    /// - If the slices are not the same length.
    pub(crate) fn insert(&mut self, mpc: Slice, zk: Slice) {
        let mpc = mpc.to_range();
        let zk = zk.to_range();

        assert_eq!(mpc.len(), zk.len(), "slices must be the same length");

        if let Some(last) = self.mpc.last() {
            if last.end > mpc.start {
                panic!("slices must be provided in ascending order");
            }
        }

        self.mpc.push(mpc);
        self.zk.push(zk);
    }

    /// Returns the corresponding allocation in the ZK VM.
    pub(crate) fn try_get(&self, mpc: Slice) -> Result<Slice, VmError> {
        let mpc_range = mpc.to_range();
        let pos = match self
            .mpc
            .binary_search_by_key(&mpc_range.start, |range| range.start)
        {
            Ok(pos) => pos,
            Err(0) => return Err(VmError::memory(format!("invalid memory slice: {mpc}"))),
            Err(pos) => pos - 1,
        };

        let candidate = &self.mpc[pos];
        if mpc_range.is_subset(candidate) {
            let offset = mpc_range.start - candidate.start;
            let start = self.zk[pos].start + offset;
            let slice = Slice::from_range_unchecked(start..start + mpc_range.len());

            Ok(slice)
        } else {
            Err(VmError::memory(format!("invalid memory slice: {mpc}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map() {
        let mut map = MemoryMap::default();
        map.insert(
            Slice::from_range_unchecked(0..10),
            Slice::from_range_unchecked(10..20),
        );

        // Range is fully contained.
        assert_eq!(
            map.try_get(Slice::from_range_unchecked(0..10)).unwrap(),
            Slice::from_range_unchecked(10..20)
        );
        // Range is subset.
        assert_eq!(
            map.try_get(Slice::from_range_unchecked(1..9)).unwrap(),
            Slice::from_range_unchecked(11..19)
        );
        // Range is not subset.
        assert!(map.try_get(Slice::from_range_unchecked(0..11)).is_err());

        // Insert another range.
        map.insert(
            Slice::from_range_unchecked(20..30),
            Slice::from_range_unchecked(30..40),
        );
        assert_eq!(
            map.try_get(Slice::from_range_unchecked(20..30)).unwrap(),
            Slice::from_range_unchecked(30..40)
        );
        assert_eq!(
            map.try_get(Slice::from_range_unchecked(21..29)).unwrap(),
            Slice::from_range_unchecked(31..39)
        );
        assert!(map.try_get(Slice::from_range_unchecked(19..21)).is_err());
    }

    #[test]
    #[should_panic]
    fn test_map_length_mismatch() {
        let mut map = MemoryMap::default();
        map.insert(
            Slice::from_range_unchecked(5..10),
            Slice::from_range_unchecked(20..30),
        );
    }
}
