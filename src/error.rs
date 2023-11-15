use thiserror::Error;


#[derive(Error, Debug)]
pub enum DeimosError {
    #[error("General error: {0}")]
    General(GeneralError),
    #[error("Redis error: {0}")]
    Redis(DatabaseError),
}

// general reusable errors
#[derive(Error, Debug)]
pub enum GeneralError {
    #[error("Failed to parse JSON")]
    ParsingError,

}


#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("Failed to acquire lock on the Redis connection")]
    LockError,
    #[error("Failed to retrieve keys from {0} dictionary from the Redis database")]
    KeysError(String),
    #[error("{0} not found")]
    NotFoundError(String),
    #[error("Failed to retrieve the input order list from the Redis database")]
    GetInputOrderError,
    #[error("Failed to write {0} to the Redis database")]
    WriteError(String),
    #[error("Failed to delete {0} from the Redis database")]
    DeleteError(String),
}