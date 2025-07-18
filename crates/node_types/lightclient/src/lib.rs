#![feature(future_join)]

pub mod lightclient;
pub use lightclient::LightClient;

#[cfg(test)]
mod tests;
