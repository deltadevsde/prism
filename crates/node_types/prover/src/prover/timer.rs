use std::{future::Future, time::Duration};

use prism_common::api::PrismApiTimer;

pub struct ProverTokioTimer;

impl PrismApiTimer for ProverTokioTimer {
    fn sleep(duration: Duration) -> impl Future<Output = ()> + Send {
        tokio::time::sleep(duration)
    }
}
