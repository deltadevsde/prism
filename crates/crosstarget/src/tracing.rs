//! Cross-platform logging abstraction that provides a unified interface for logging
//! across `WebAssembly` (browser console) and native (tracing) targets.

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {{
        #[cfg(target_arch = "wasm32")]
        {
            $crate::tracing::__wasm_log_info(&format!($($arg)*))
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            ::tracing::info!($($arg)*)
        }
    }};
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {{
        #[cfg(target_arch = "wasm32")]
        {
            $crate::tracing::__wasm_log_warn(&format!($($arg)*))
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            ::tracing::warn!($($arg)*)
        }
    }};
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {{
        #[cfg(target_arch = "wasm32")]
        {
            $crate::tracing::__wasm_log_error(&format!($($arg)*))
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            ::tracing::error!($($arg)*)
        }
    }};
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {{
        #[cfg(target_arch = "wasm32")]
        {
            $crate::tracing::__wasm_log_debug(&format!($($arg)*))
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            ::tracing::debug!($($arg)*)
        }
    }};
}

#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {{
        #[cfg(target_arch = "wasm32")]
        {
            $crate::tracing::__wasm_log_trace(&format!($($arg)*))
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            ::tracing::trace!($($arg)*)
        }
    }};
}

// Hidden helper functions for WASM logging macros
#[cfg(target_arch = "wasm32")]
#[doc(hidden)]
pub fn __wasm_log_info(msg: &str) {
    web_sys::console::log_1(&msg.into());
}

#[cfg(target_arch = "wasm32")]
#[doc(hidden)]
pub fn __wasm_log_warn(msg: &str) {
    web_sys::console::warn_1(&msg.into());
}

#[cfg(target_arch = "wasm32")]
#[doc(hidden)]
pub fn __wasm_log_error(msg: &str) {
    web_sys::console::error_1(&msg.into());
}

#[cfg(target_arch = "wasm32")]
#[doc(hidden)]
pub fn __wasm_log_debug(msg: &str) {
    web_sys::console::debug_1(&msg.into());
}

#[cfg(target_arch = "wasm32")]
#[doc(hidden)]
pub fn __wasm_log_trace(msg: &str) {
    web_sys::console::trace_1(&msg.into());
}
