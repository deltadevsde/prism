pub mod celestia;
pub mod client;
pub mod commands;
pub mod error;
pub mod worker;
pub mod worker_communication;

#[cfg(feature = "console_error_panic_hook")]
pub fn set_panic_hook() {
    console_error_panic_hook::set_once();
}
