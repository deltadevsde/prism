use std::time::Duration;

/// `DA_RETRY_COUNT` determines how many times to retry epoch submission.
pub const DA_RETRY_COUNT: u64 = 5;
/// `DA_RETRY_COUNT` determines how long to wait between failed submissions.
pub const DA_RETRY_INTERVAL: Duration = Duration::from_secs(5);
/// `CHANNEL_BUFFER_SIZE` determines the default channel size.
pub const CHANNEL_BUFFER_SIZE: usize = 5;
