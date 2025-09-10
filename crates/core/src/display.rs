use rangeset::RangeSet;

pub(crate) struct FmtRangeSet<'a>(pub &'a RangeSet<usize>);

impl<'a> std::fmt::Display for FmtRangeSet<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("{")?;
        for range in self.0.iter_ranges() {
            write!(f, "{}..{}", range.start, range.end)?;
            if range.end < self.0.end().unwrap_or(0) {
                f.write_str(", ")?;
            }
        }
        f.write_str("}")
    }
}
