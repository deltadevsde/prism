use crate::token::Token;
use std::{fmt, fmt::Debug};

/// Naive `JoinHandle` implementation.
pub struct JoinHandle(Token);

impl JoinHandle {
    /// Await for the handle to return
    pub async fn join(&self) {
        self.0.triggered().await;
    }
}

impl Debug for JoinHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JoinHandle { .. }")
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn spawn<F>(future: F) -> JoinHandle
where
    F: Future<Output = ()> + Send + 'static,
{
    let token = Token::new();
    let guard = token.trigger_drop_guard();

    tokio::spawn(async move {
        let _guard = guard;
        future.await;
    });

    JoinHandle(token)
}

#[cfg(target_arch = "wasm32")]
pub fn spawn<F>(future: F) -> JoinHandle
where
    F: Future<Output = ()> + 'static,
{
    let token = Token::new();
    let guard = token.trigger_drop_guard();

    wasm_bindgen_futures::spawn_local(async move {
        let _guard = guard;
        future.await;
    });

    JoinHandle(token)
}
