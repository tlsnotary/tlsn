use super::data_doc::{Range, RoundSize};

// salt for the public data commitment
type Salt = [u8; 128];

enum Error {
    Error,
}

#[derive(Clone)]
/// byte range with the corresponding bytes from that range
struct RangeWithPublicData {
    pub range: Range,
    pub data: Vec<u8>,
}

// public data for one round of notarization
pub struct PublicDataOneRound {
    // Note that the range bounds are relative to this notarization round
    // Ranges must not overlap and must be in an ascending order.

    // It is not permitted (to simplify the code) that the whole request or
    // the whole response is private. Realistically, at least some headers in
    // the request/response will be made public.
    // TODO: for non-HTTP cases we may reconsider this assumption

    // public data in the request
    pub request: Vec<RangeWithPublicData>,
    // public data in the response
    response: Vec<RangeWithPublicData>,
    // the commitment to request+response public labels of
    // this round is salted
    salt: Salt,
}

impl PublicDataOneRound {
    // performs various sanity checks on the ranges.
    // `round_size` is supposed to be signed by the Notary
    pub fn check(&self, round_size: &RoundSize) -> bool {
        if self.request.is_some()
            && !self.check_internal(self.request.unwrap(), round_size.request as usize)
        {
            return false;
        }
        if self.response.is_some()
            && !self.check_internal(self.response.unwrap(), round_size.response as usize)
        {
            return false;
        }

        true
    }

    // checks that no public ranges overlap
    // checks that ranges are in an ascending order
    // checks that amount of public data is not larger than request/response total size

    // sanity checks ranges for one Direction of one round
    fn check_internal(&self, ranges: Vec<RangeWithPublicData>, round_size: usize) -> bool {
        // total amount of bytes in all the ranges
        let mut ranges_total = 0u32;

        // ranges must be valid
        for r in ranges.iter() {
            ranges_total += r.range.end - r.range.start;
            if r.range.end <= r.range.start {
                return false;
            }
        }

        // ranges must not overlap and be ascending
        for pair in ranges.windows(2) {
            if pair[0].range.end - 1 < pair[1].range.start {
                return false;
            }
        }

        // total from all ranges must not exceed the size of the round
        if (ranges_total as usize) > round_size {
            return false;
        }

        true
    }
}

// public data from all rounds of notarization
pub type PublicData = Vec<PublicDataOneRound>;
