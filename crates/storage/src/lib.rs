pub mod database;
mod factory;
pub mod inmemory;
pub mod redis;
pub mod rocksdb;

#[cfg(test)]
mod tests;

pub use crate::{
    database::Database,
    factory::{DatabaseConfig, create_storage},
    redis::RedisConnection,
};
