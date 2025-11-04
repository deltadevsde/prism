#[derive(Error, Debug)]
pub enum PrismError {
    #[error(transparent)]
    General(#[from] GeneralError),
    #[error(transparent)]
    Database(#[from] DatabaseError),
    #[error(transparent)]
    DataAvailability(#[from] DataAvailabilityError),
    #[error(transparent)]
    Proof(#[from] ProofError),
    #[error("config error: {0}")]
    ConfigError(String),
    #[error(transparent)]
    Other(#[from] AnyhowError),
}
