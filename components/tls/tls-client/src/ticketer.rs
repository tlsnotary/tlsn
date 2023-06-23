use std::time;

/// The timebase for expiring and rolling tickets and ticketing
/// keys.  This is UNIX wall time in seconds.
///
/// This is guaranteed to be on or after the UNIX epoch.
#[derive(Clone, Copy, Debug)]
pub struct TimeBase(time::Duration);

impl TimeBase {
    #[inline]
    pub fn now() -> Result<Self, time::SystemTimeError> {
        Ok(Self(
            time::SystemTime::now().duration_since(time::UNIX_EPOCH)?,
        ))
    }

    #[inline]
    pub fn as_secs(&self) -> u64 {
        self.0.as_secs()
    }
}
