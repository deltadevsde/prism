//! Cross-platform logging abstraction that provides a unified interface for logging
//! across `WebAssembly` (browser console) and native (tracing) targets.

#[cfg(target_arch = "wasm32")]
pub use console::{debug, error, info, trace, warn};
#[cfg(not(target_arch = "wasm32"))]
pub use tracing_macros::{debug, error, info, trace, warn};

#[cfg(target_arch = "wasm32")]
mod console {
    pub fn info(msg: &str) {
        web_sys::console::log_1(&msg.into());
    }

    pub fn warn(msg: &str) {
        web_sys::console::warn_1(&msg.into());
    }

    pub fn error(msg: &str) {
        web_sys::console::error_1(&msg.into());
    }

    pub fn debug(msg: &str) {
        web_sys::console::debug_1(&msg.into());
    }

    pub fn trace(msg: &str) {
        web_sys::console::trace_1(&msg.into());
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod tracing_macros {
    pub fn info(msg: &str) {
        tracing::info!("{}", msg);
    }

    pub fn warn(msg: &str) {
        tracing::warn!("{}", msg);
    }

    pub fn error(msg: &str) {
        tracing::error!("{}", msg);
    }

    pub fn debug(msg: &str) {
        tracing::debug!("{}", msg);
    }

    pub fn trace(msg: &str) {
        tracing::trace!("{}", msg);
    }
}
