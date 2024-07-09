use thiserror::Error;

#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("acquiring database lock")]
    LockError,
    #[error("retrieving keys from {0} dictionary")]
    KeysError(String),
    #[error("{0} not found")]
    NotFoundError(String),
    #[error("retreiving input order list")]
    GetInputOrderError,
    #[error("writing {0} to database")]
    WriteError(String),
    #[error("deleting {0} from database")]
    DeleteError(String),
    #[error(transparent)]
    GeneralError(#[from] GeneralError),
}
