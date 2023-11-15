use thiserror::Error;


#[derive(Error, Debug)]
pub enum DeimosError {
    #[error("General error: {0}")]
    General(GeneralError),
    #[error("Database error: {0}")]
    Database(DatabaseError),
}

// general reusable errors
#[derive(Error, Debug)]
pub enum GeneralError {
    #[error("Failed to parse JSON")]
    ParsingError,

}


#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("Failed to acquire lock on the Database connection")]
    LockError,
    #[error("Failed to retrieve keys from {0} dictionary from the Database database")]
    KeysError(String),
    #[error("{0} not found")]
    NotFoundError(String),
    #[error("Failed to retrieve the input order list from the Database database")]
    GetInputOrderError,
    #[error("Failed to write {0} to the Database database")]
    WriteError(String),
    #[error("Failed to delete {0} from the Database database")]
    DeleteError(String),
}