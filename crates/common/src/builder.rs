use prism_keys::{SigningKey, VerifyingKey};

use crate::{
    account::Account,
    api::{noop::NoopPrismApi, PendingTransaction, PrismApi, PrismApiError},
    digest::Digest,
    operation::{Operation, ServiceChallenge, ServiceChallengeInput, SignatureBundle},
    transaction::{Transaction, TransactionError, UnsignedTransaction},
};

pub struct RequestBuilder<'a, P = NoopPrismApi> {
    prism: Option<&'a P>,
}

impl<'a, P> RequestBuilder<'a, P>
where
    P: PrismApi,
{
    pub fn new() -> Self {
        Self { prism: None }
    }

    pub fn new_with_prism(prism: &'a P) -> Self {
        Self { prism: Some(prism) }
    }

    pub fn create_account(self) -> CreateAccountRequestBuilder<'a, P> {
        CreateAccountRequestBuilder::new(self.prism)
    }

    pub fn register_service(self) -> RegisterServiceRequestBuilder<'a, P> {
        RegisterServiceRequestBuilder::new(self.prism)
    }

    pub fn to_modify_account(self, account: &Account) -> ModifyAccountRequestBuilder<'a, P> {
        ModifyAccountRequestBuilder::new(self.prism, account)
    }

    pub fn continue_transaction(
        self,
        unsigned_transaction: UnsignedTransaction,
    ) -> SigningTransactionRequestBuilder<'a, P> {
        SigningTransactionRequestBuilder::new(self.prism, unsigned_transaction)
    }
}

impl<P> Default for RequestBuilder<'_, P>
where
    P: PrismApi,
{
    fn default() -> Self {
        Self::new()
    }
}

pub struct CreateAccountRequestBuilder<'a, P>
where
    P: PrismApi,
{
    prism: Option<&'a P>,
    id: String,
    service_id: String,
    key: Option<VerifyingKey>,
}

impl<'a, P> CreateAccountRequestBuilder<'a, P>
where
    P: PrismApi,
{
    pub fn new(prism: Option<&'a P>) -> Self {
        Self {
            prism,
            id: String::new(),
            service_id: String::new(),
            key: None,
        }
    }

    pub fn with_id(mut self, id: String) -> Self {
        self.id = id;
        self
    }

    pub fn with_key(mut self, key: VerifyingKey) -> Self {
        self.key = Some(key);
        self
    }

    pub fn for_service_with_id(mut self, service_id: String) -> Self {
        self.service_id = service_id;
        self
    }

    pub fn meeting_signed_challenge(
        self,
        service_signing_key: &SigningKey,
    ) -> Result<SigningTransactionRequestBuilder<'a, P>, TransactionError> {
        let Some(key) = self.key else {
            return Err(TransactionError::MissingKey);
        };

        // This could be some external service signing account creation credentials
        let hash = Digest::hash_items(&[
            self.id.as_bytes(),
            self.service_id.as_bytes(),
            &key.to_bytes(),
        ]);
        let signature =
            service_signing_key.sign(hash).map_err(|_| TransactionError::SigningFailed)?;

        let operation = Operation::CreateAccount {
            id: self.id.clone(),
            service_id: self.service_id,
            challenge: ServiceChallengeInput::Signed(signature.clone()),
            key,
        };

        operation.validate_basic().map_err(|e| TransactionError::InvalidOp(e.to_string()))?;

        let unsigned_transaction = UnsignedTransaction {
            id: self.id,
            operation,
            nonce: 0,
        };
        Ok(SigningTransactionRequestBuilder::new(
            self.prism,
            unsigned_transaction,
        ))
    }
}

pub struct RegisterServiceRequestBuilder<'a, P>
where
    P: PrismApi,
{
    prism: Option<&'a P>,
    id: String,
    key: Option<VerifyingKey>,
}

impl<'a, P> RegisterServiceRequestBuilder<'a, P>
where
    P: PrismApi,
{
    pub fn new(prism: Option<&'a P>) -> Self {
        Self {
            prism,
            id: String::new(),
            key: None,
        }
    }

    pub fn with_id(mut self, id: String) -> Self {
        self.id = id;
        self
    }

    pub fn with_key(mut self, key: VerifyingKey) -> Self {
        self.key = Some(key);
        self
    }

    pub fn requiring_signed_challenge(
        self,
        challenge_key: VerifyingKey,
    ) -> Result<SigningTransactionRequestBuilder<'a, P>, TransactionError> {
        let Some(key) = self.key else {
            return Err(TransactionError::MissingKey);
        };

        let operation = Operation::RegisterService {
            id: self.id.clone(),
            creation_gate: ServiceChallenge::Signed(challenge_key),
            key,
        };

        operation.validate_basic().map_err(|e| TransactionError::InvalidOp(e.to_string()))?;

        let unsigned_transaction = UnsignedTransaction {
            id: self.id,
            operation,
            nonce: 0,
        };
        Ok(SigningTransactionRequestBuilder::new(
            self.prism,
            unsigned_transaction,
        ))
    }
}

pub struct ModifyAccountRequestBuilder<'a, P>
where
    P: PrismApi,
{
    prism: Option<&'a P>,
    id: String,
    nonce: u64,
}

impl<'a, P> ModifyAccountRequestBuilder<'a, P>
where
    P: PrismApi,
{
    pub fn new(prism: Option<&'a P>, account: &Account) -> Self {
        Self {
            prism,
            id: account.id().to_string(),
            nonce: account.nonce(),
        }
    }

    pub fn add_key(
        self,
        key: VerifyingKey,
    ) -> Result<SigningTransactionRequestBuilder<'a, P>, TransactionError> {
        self.validate_id_and_nonce()?;
        let operation = Operation::AddKey { key };
        operation.validate_basic().map_err(|e| TransactionError::InvalidOp(e.to_string()))?;
        let unsigned_transaction = UnsignedTransaction {
            id: self.id,
            operation,
            nonce: self.nonce,
        };
        Ok(SigningTransactionRequestBuilder::new(
            self.prism,
            unsigned_transaction,
        ))
    }

    pub fn revoke_key(
        self,
        key: VerifyingKey,
    ) -> Result<SigningTransactionRequestBuilder<'a, P>, TransactionError> {
        self.validate_id_and_nonce()?;
        let operation = Operation::RevokeKey { key };
        operation.validate_basic().map_err(|e| TransactionError::InvalidOp(e.to_string()))?;
        let unsigned_transaction = UnsignedTransaction {
            id: self.id,
            operation,
            nonce: self.nonce,
        };
        Ok(SigningTransactionRequestBuilder::new(
            self.prism,
            unsigned_transaction,
        ))
    }

    pub fn add_data(
        self,
        data: Vec<u8>,
        data_signature: SignatureBundle,
    ) -> Result<SigningTransactionRequestBuilder<'a, P>, TransactionError> {
        self.validate_id_and_nonce()?;
        let operation = Operation::AddData {
            data,
            data_signature,
        };
        operation.validate_basic().map_err(|e| TransactionError::InvalidOp(e.to_string()))?;
        let unsigned_transaction = UnsignedTransaction {
            id: self.id,
            operation,
            nonce: self.nonce,
        };
        Ok(SigningTransactionRequestBuilder::new(
            self.prism,
            unsigned_transaction,
        ))
    }

    pub fn set_data(
        self,
        data: Vec<u8>,
        data_signature: SignatureBundle,
    ) -> Result<SigningTransactionRequestBuilder<'a, P>, TransactionError> {
        self.validate_id_and_nonce()?;
        let operation = Operation::SetData {
            data,
            data_signature,
        };
        operation.validate_basic().map_err(|e| TransactionError::InvalidOp(e.to_string()))?;
        let unsigned_transaction = UnsignedTransaction {
            id: self.id,
            operation,
            nonce: self.nonce,
        };
        Ok(SigningTransactionRequestBuilder::new(
            self.prism,
            unsigned_transaction,
        ))
    }

    fn validate_id_and_nonce(&self) -> Result<(), TransactionError> {
        if self.id.len() < 3 {
            return Err(TransactionError::InvalidOp(format!(
                "Invalid ID: {}",
                self.id
            )));
        }

        if self.nonce == 0 {
            return Err(TransactionError::InvalidNonce(self.nonce));
        }
        Ok(())
    }
}

pub struct SigningTransactionRequestBuilder<'a, P>
where
    P: PrismApi,
{
    prism: Option<&'a P>,
    unsigned_transaction: UnsignedTransaction,
}

impl<'a, P> SigningTransactionRequestBuilder<'a, P>
where
    P: PrismApi,
{
    pub fn new(prism: Option<&'a P>, unsigned_transaction: UnsignedTransaction) -> Self {
        Self {
            prism,
            unsigned_transaction,
        }
    }

    pub fn sign(
        self,
        signing_key: &SigningKey,
    ) -> Result<SendingTransactionRequestBuilder<'a, P>, TransactionError> {
        let transaction = self.unsigned_transaction.sign(signing_key)?;
        Ok(SendingTransactionRequestBuilder::new(
            self.prism,
            transaction,
        ))
    }

    pub fn with_external_signature(
        self,
        signature_bundle: SignatureBundle,
    ) -> SendingTransactionRequestBuilder<'a, P> {
        SendingTransactionRequestBuilder::new(
            self.prism,
            self.unsigned_transaction.externally_signed(signature_bundle),
        )
    }

    pub fn transaction(self) -> UnsignedTransaction {
        self.unsigned_transaction
    }
}

pub struct SendingTransactionRequestBuilder<'a, P>
where
    P: PrismApi,
{
    prism: Option<&'a P>,
    transaction: Transaction,
}

impl<'a, P> SendingTransactionRequestBuilder<'a, P>
where
    P: PrismApi,
{
    pub fn new(prism: Option<&'a P>, transaction: Transaction) -> Self {
        Self { prism, transaction }
    }

    pub async fn send(
        self,
    ) -> Result<impl PendingTransaction<'a, Timer = P::Timer>, PrismApiError> {
        let Some(prism) = self.prism else {
            return Err(TransactionError::MissingSender.into());
        };

        prism.post_transaction(self.transaction).await
    }

    pub fn transaction(self) -> Transaction {
        self.transaction
    }
}
