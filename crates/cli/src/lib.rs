#![feature(coverage_attribute)]
#![cfg(not(target_arch = "wasm32"))]

pub mod apply_args;
pub mod cli_args;
pub mod config;
pub mod error;
pub mod node_types;

mod file_utils;

#[cfg(test)]
mod tests;
