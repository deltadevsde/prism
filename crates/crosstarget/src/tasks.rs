use std::{
    fmt::{self, Debug},
    sync::{Mutex, PoisonError},
};
use thiserror::Error;

use crate::{token::Token, warn};

/// Naive `JoinHandle` as the least common denominator for all targets.
pub struct JoinHandle(Token);

impl JoinHandle {
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

pub struct TaskManager {
    inner: Mutex<Inner>,
}

struct Inner {
    state: State,
    token: Option<Token>,
    handles: Vec<JoinHandle>,
}

enum State {
    Idle,
    Running,
    Stopping,
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum TaskManagerError {
    #[error("currently stopping")]
    Stopping,
    #[error("not running")]
    NotRunning,
    #[error("internal lock poisoned")]
    Poisoned,
}

impl<T> From<PoisonError<T>> for TaskManagerError {
    fn from(_: PoisonError<T>) -> Self {
        Self::Poisoned
    }
}

impl TaskManager {
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                state: State::Idle,
                token: None,
                handles: Vec::new(),
            }),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn spawn<F, Fut>(&self, task_fn: F) -> Result<(), TaskManagerError>
    where
        F: FnOnce(Token) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let mut inner = self.inner.lock()?;

        let token = match inner.state {
            State::Idle => {
                let t = Token::new();
                inner.token = Some(t.clone());
                inner.state = State::Running;
                t
            }
            State::Running => inner.token.as_ref().unwrap().clone(),
            State::Stopping => return Err(TaskManagerError::Stopping),
        };

        let handle = spawn(task_fn(token));
        inner.handles.push(handle);
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    pub fn spawn<F, Fut>(&self, task_fn: F) -> Result<(), TaskManagerError>
    where
        F: FnOnce(Token) -> Fut,
        Fut: Future<Output = ()> + 'static,
    {
        let mut inner = self.inner.lock()?;

        let token = match inner.state {
            State::Idle => {
                let t = Token::new();
                inner.token = Some(t.clone());
                inner.state = State::Running;
                t
            }
            State::Running => inner.token.as_ref().unwrap().clone(),
            State::Stopping => return Err(TaskManagerError::Stopping),
        };

        let handle = spawn(task_fn(token));
        inner.handles.push(handle);
        Ok(())
    }

    pub async fn stop(&self) -> Result<(), TaskManagerError> {
        let (handles, token) = {
            let mut inner = self.inner.lock()?;

            match inner.state {
                State::Idle => {
                    warn!("stop called, but tasks were already stopped");
                    return Ok(());
                }
                State::Running => {
                    inner.state = State::Stopping;
                    (std::mem::take(&mut inner.handles), inner.token.take())
                }
                State::Stopping => return Err(TaskManagerError::Stopping),
            }
        };

        if let Some(t) = token {
            t.trigger();
        }

        for handle in handles {
            handle.join().await;
        }

        self.inner.lock()?.state = State::Idle;
        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.inner.lock().map(|inner| matches!(inner.state, State::Running)).unwrap_or(false)
    }
}

impl Default for TaskManager {
    fn default() -> Self {
        Self::new()
    }
}
