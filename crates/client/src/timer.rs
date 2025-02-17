use std::{future::Future, time::Duration};

use prism_api::api::PrismApiTimer;

pub struct PrismHttpTokioTimer;

impl PrismApiTimer for PrismHttpTokioTimer {
    fn sleep(duration: Duration) -> impl Future<Output = ()> + Send {
        tokio::time::sleep(duration)
    }
}
