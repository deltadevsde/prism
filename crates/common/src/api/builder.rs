use crate::{
    account::Account,
    digest::Digest,
    operation::{Operation, ServiceChallenge, ServiceChallengeInput, SignatureBundle},
    transaction::{Transaction, TransactionError, UnsignedTransaction},
};
use prism_keys::{SigningKey, VerifyingKey};

use crate::api::{PendingTransaction, PrismApi};

pub struct RequestBuilder<'a, P>
where
    P: PrismApi,
{
    prism: &'a P,
}

impl<'a, P> RequestBuilder<'a, P>
where
    P: PrismApi,
{
    pub fn new(prism: &'a P) -> Self {
        Self { prism }
    }

    pub fn create_account(self) -> CreateAccountRequestBuilder<'a, P> {
        CreateAccountRequestBuilder::new(self.prism)
    }

    pub fn register_service(self) -> RegisterServiceRequestBuilder<'a, P> {
        RegisterServiceRequestBuilder::new(self.prism)
    }

    pub fn modify_existing(self) -> ModifyAccountRequestBuilder<'a, P> {
        ModifyAccountRequestBuilder::new(self.prism)
    }
}

pub struct CreateAccountRequestBuilder<'a, P>
where
    P: PrismApi,
{
    prism: &'a P,
    id: String,
    service_id: String,
    key: Option<VerifyingKey>,
}

impl<'a, P> CreateAccountRequestBuilder<'a, P>
where
    P: PrismApi,
{
    pub fn new(prism: &'a P) -> Self {
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
        let signature = service_signing_key.sign(&hash.to_bytes());

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
    prism: &'a P,
    id: String,
    key: Option<VerifyingKey>,
}

impl<'a, P> RegisterServiceRequestBuilder<'a, P>
where
    P: PrismApi,
{
    pub fn new(prism: &'a P) -> Self {
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
    prism: &'a P,
    id: String,
    nonce: u64,
}

impl<'a, P> ModifyAccountRequestBuilder<'a, P>
where
    P: PrismApi,
{
    pub fn new(prism: &'a P) -> Self {
        Self {
            prism,
            id: String::new(),
            nonce: 0,
        }
    }

    pub fn for_account(mut self, account: &Account) -> Self {
        self.id = account.id().to_string();
        self.nonce = account.nonce();
        self
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
    prism: &'a P,
    transaction: UnsignedTransaction,
}

impl<'a, P> SigningTransactionRequestBuilder<'a, P>
where
    P: PrismApi,
{
    pub fn new(prism: &'a P, transaction: UnsignedTransaction) -> Self {
        Self { prism, transaction }
    }

    pub fn sign(
        self,
        signing_key: &SigningKey,
    ) -> Result<SendingTransactionRequestBuilder<'a, P>, TransactionError> {
        let transaction = self.transaction.sign(signing_key)?;
        Ok(SendingTransactionRequestBuilder::new(
            self.prism,
            transaction,
        ))
    }
}

pub struct SendingTransactionRequestBuilder<'a, P>
where
    P: PrismApi,
{
    prism: &'a P,
    transaction: Transaction,
}

impl<'a, P> SendingTransactionRequestBuilder<'a, P>
where
    P: PrismApi,
{
    pub fn new(prism: &'a P, transaction: Transaction) -> Self {
        Self { prism, transaction }
    }

    pub async fn send(self) -> Result<PendingTransaction<'a, P>, P::Error> {
        self.prism.post_transaction(&self.transaction).await?;
        Ok(PendingTransaction::new(self.prism, self.transaction))
    }
}
