use chrono::{Datelike, Local, NaiveDate};
use serde::{Deserialize, Serialize};
use std::fmt;
use tlsn::transcript::{hash::PlaintextHash, Direction, TranscriptCommitment};

#[derive(Serialize, Deserialize, Debug)]
pub struct ZKProofBundle {
    pub vk: Vec<u8>,
    pub proof: Vec<u8>,
    pub check_date: String,
}

// extract commitment from prover output
pub fn received_commitments(transcript_commitments: &[TranscriptCommitment]) -> Vec<PlaintextHash> {
    transcript_commitments
        .iter()
        .filter(|commitment| {
            if let TranscriptCommitment::Hash(hash) = commitment {
                hash.direction == Direction::Received
            } else {
                false
            }
        })
        .map(|commitment| {
            if let TranscriptCommitment::Hash(hash) = commitment {
                hash.clone()
            } else {
                unreachable!()
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckDate {
    date: NaiveDate,
}

impl CheckDate {
    /// Create a new CheckDate from current local time
    pub fn now() -> Self {
        Self {
            date: Local::now().date_naive(),
        }
    }

    /// Parse from YYYY-MM-DD format
    pub fn from_str(date_str: &str) -> Result<Self, String> {
        let date = NaiveDate::parse_from_str(date_str, "%Y-%m-%d")
            .map_err(|e| format!("Invalid date format '{}': {}", date_str, e))?;

        Ok(Self { date })
    }

    /// Get the year component
    pub fn year(&self) -> i32 {
        self.date.year()
    }

    /// Get the month component (1-12)
    pub fn month(&self) -> u32 {
        self.date.month()
    }

    /// Get the day component (1-31)
    pub fn day(&self) -> u32 {
        self.date.day()
    }
}

impl fmt::Display for CheckDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.date.format("%Y-%m-%d"))
    }
}

impl From<NaiveDate> for CheckDate {
    fn from(date: NaiveDate) -> Self {
        Self { date }
    }
}

impl From<CheckDate> for NaiveDate {
    fn from(check_date: CheckDate) -> Self {
        check_date.date
    }
}
