use aws_config::{BehaviorVersion, Region, retry::RetryConfigBuilder};
use aws_sdk_s3::{
    Client as S3Client,
    config::{Credentials, SharedCredentialsProvider},
    primitives::DateTime,
    types::{ObjectLockLegalHoldStatus, ObjectLockMode},
};
use futures::future::try_join_all;
use prism_common::transaction::Transaction;
use prism_errors::DataAvailabilityError;
use prism_serde::binary::{FromBinary, ToBinary};
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::{debug, info, trace, warn};

use crate::{
    FinalizedEpoch,
    aws::{AwsCredentialsConfig, AwsFullNodeDAConfig, AwsLightClientDAConfig},
};

use thiserror::Error;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AwsDaMetaInfo {
    pub current_height: u64,
}

#[derive(Error, Debug)]
pub enum AwsDaClientError {
    #[error("Failed to initialize AWS client: {0}")]
    InitializationError(String),

    #[error("Request failed: {0}")]
    RequestFailed(String),

    #[error("Upload failed: {0}")]
    UploadFailed(String),
}

impl From<AwsDaClientError> for DataAvailabilityError {
    fn from(err: AwsDaClientError) -> Self {
        match err {
            AwsDaClientError::InitializationError(msg) => Self::InitializationError(msg),
            AwsDaClientError::RequestFailed(msg) => Self::NetworkError(msg),
            AwsDaClientError::UploadFailed(msg) => Self::SubmissionError(msg),
        }
    }
}

/// AWS S3 client facade for data availability operations.
///
/// This client handles S3-specific operations including epoch downloading,
/// height querying, and bucket access management.
#[derive(Clone)]
pub struct AwsDataAvailabilityClient {
    /// S3 client for AWS operations
    s3_client: S3Client,

    epochs_bucket: String,
    transactions_bucket: Option<String>,
    metadata_bucket: String,
    key_prefix: String,
    retention_days: u32,
    enable_legal_holds: bool,
    max_concurrent_uploads: u32,
}

impl AwsDataAvailabilityClient {
    pub async fn new_from_light_da_config(
        config: AwsLightClientDAConfig,
    ) -> Result<Self, AwsDaClientError> {
        // Validate configuration
        Self::verify_bucket_name(&config.epochs_bucket)?;
        Self::verify_bucket_name(&config.metadata_bucket)?;

        let s3_client = Self::create_s3_client(
            config.region.clone(),
            config.endpoint,
            config.max_retries,
            config.max_timeout,
            &config.credentials,
        )
        .await?;

        // Verify bucket access by attempting to list objects
        Self::verify_bucket_access(&s3_client, &config.epochs_bucket).await?;
        Self::verify_bucket_access(&s3_client, &config.metadata_bucket).await?;

        // Verify WORM configuration
        Self::verify_object_lock_enabled(&s3_client, &config.epochs_bucket).await?;

        debug!(
            "AWS DA client initialized for region '{}', epochs bucket '{}', transactions bucket 'None'",
            &config.region, &config.epochs_bucket
        );

        Ok(Self {
            s3_client,
            epochs_bucket: config.epochs_bucket,
            transactions_bucket: None,
            metadata_bucket: config.metadata_bucket,
            key_prefix: config.key_prefix,
            retention_days: 0,
            enable_legal_holds: false,
            max_concurrent_uploads: 1,
        })
    }

    pub async fn new_from_full_da_config(
        config: AwsFullNodeDAConfig,
    ) -> Result<Self, AwsDaClientError> {
        // Validate configuration
        Self::verify_bucket_name(&config.light_client.epochs_bucket)?;
        Self::verify_bucket_name(&config.transactions_bucket)?;
        Self::verify_bucket_name(&config.light_client.metadata_bucket)?;

        let s3_client = Self::create_s3_client(
            config.light_client.region.clone(),
            config.light_client.endpoint,
            config.light_client.max_retries,
            config.light_client.max_timeout,
            &config.light_client.credentials,
        )
        .await?;

        // Verify bucket access by attempting to list objects
        Self::verify_bucket_access(&s3_client, &config.light_client.epochs_bucket).await?;
        Self::verify_bucket_access(&s3_client, &config.transactions_bucket).await?;
        Self::verify_bucket_access(&s3_client, &config.light_client.metadata_bucket).await?;

        // Verify WORM configuration
        Self::verify_object_lock_enabled(&s3_client, &config.light_client.epochs_bucket).await?;
        Self::verify_object_lock_enabled(&s3_client, &config.transactions_bucket).await?;

        debug!(
            "AWS DA client initialized for region '{}', epochs bucket '{}', transactions bucket '{}'",
            &config.light_client.region,
            &config.light_client.epochs_bucket,
            &config.transactions_bucket
        );

        Ok(Self {
            s3_client,
            epochs_bucket: config.light_client.epochs_bucket,
            transactions_bucket: Some(config.transactions_bucket),
            metadata_bucket: config.light_client.metadata_bucket,
            key_prefix: config.light_client.key_prefix,
            retention_days: config.retention_days,
            enable_legal_holds: config.enable_legal_holds,
            max_concurrent_uploads: config.max_concurrent_uploads,
        })
    }

    /// Gets the highest available epoch height from S3 metadata.
    pub async fn fetch_height(&self) -> Result<Option<u64>, AwsDaClientError> {
        let current_height = self.fetch_metadata().await?.map(|info| info.current_height);
        Ok(current_height)
    }

    /// Fetches and parses epoch data from S3.
    pub async fn fetch_epochs(&self, height: u64) -> Result<Vec<FinalizedEpoch>, AwsDaClientError> {
        let padded_height = format!("{:012}", height);
        let epochs_path = format!("{}epochs/{}/", self.key_prefix, padded_height);

        self.fetch_all_from_s3(&self.epochs_bucket, &epochs_path).await
    }

    /// Fetches and parses transaction data from S3.
    pub async fn fetch_transactions(
        &self,
        height: u64,
    ) -> Result<Vec<Transaction>, AwsDaClientError> {
        let Some(transactions_bucket) = &self.transactions_bucket else {
            return Err(AwsDaClientError::InitializationError(
                "No transactions bucket specified".to_string(),
            ));
        };

        trace!("Querying transactions at height {}", height);

        let padded_height = format!("{:012}", height);
        let transactions_path = format!("{}transactions/{}/", self.key_prefix, padded_height);

        self.fetch_all_from_s3::<Transaction>(transactions_bucket, &transactions_path).await
    }

    /// Submits transaction data to S3.
    pub async fn submit_transactions(
        &self,
        transactions: Vec<Transaction>,
        offset: u64,
        height: u64,
    ) -> Result<(), AwsDaClientError> {
        if transactions.is_empty() {
            return Err(AwsDaClientError::UploadFailed(
                "No transactions to submit".to_string(),
            ));
        }

        let Some(transactions_bucket) = &self.transactions_bucket else {
            return Err(AwsDaClientError::InitializationError(
                "No transactions bucket specified".to_string(),
            ));
        };

        debug!("Submitting {} transactions to S3", transactions.len());

        // Prepare upload tasks
        let upload_tasks: Vec<_> = transactions
            .into_iter()
            .enumerate()
            .map(|(index, transaction)| {
                let index = u64::try_from(index).unwrap();
                let bucket = transactions_bucket.clone();
                let key = self.transaction_key(height, offset + index);

                async move { self.upload_with_worm(&bucket, &key, transaction).await }
            })
            .collect();

        let max_concurrent_uploads = self.max_concurrent_uploads.try_into().map_err(|e| {
            AwsDaClientError::UploadFailed(format!(
                "Failed to convert max concurrent uploads to usize: {}",
                e
            ))
        })?;

        // Execute uploads with concurrency limit
        let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent_uploads));
        let upload_futures: Vec<_> = upload_tasks
            .into_iter()
            .map(|task| {
                let sem = semaphore.clone();
                async move {
                    let _permit = sem.acquire().await.unwrap();
                    task.await
                }
            })
            .collect();
        let upload_futures_count = upload_futures.len();

        try_join_all(upload_futures).await.map_err(|e| {
            AwsDaClientError::UploadFailed(format!("Failed to await all uploads: {}", e))
        })?;

        info!(
            "Successfully submitted {} transactions to S3 at height {} with {} day retention",
            upload_futures_count, height, self.retention_days
        );

        Ok(())
    }

    /// Submits a finalized epoch to S3.
    pub async fn submit_finalized_epoch(
        &self,
        epoch: FinalizedEpoch,
        height: u64,
    ) -> Result<(), AwsDaClientError> {
        // TODO: Get latest height or use cached height or transfer it as parameter?
        let epoch_key = self.epoch_key(height, epoch.height);
        self.upload_with_worm(&self.epochs_bucket, &epoch_key, epoch).await
    }

    async fn create_s3_client(
        region: String,
        endpoint: Option<String>,
        max_retries: u32,
        max_timeout: Duration,
        credentials: &AwsCredentialsConfig,
    ) -> Result<S3Client, AwsDaClientError> {
        let region = Region::new(region);
        let retry_config =
            RetryConfigBuilder::new().max_attempts(max_retries).max_backoff(max_timeout).build();
        let mut config_loader = aws_config::defaults(BehaviorVersion::v2025_01_17())
            .region(region.clone())
            .retry_config(retry_config);

        if let Some(endpoint) = endpoint {
            config_loader = config_loader.endpoint_url(endpoint);
        }

        match credentials {
            AwsCredentialsConfig::Default { profile } => {
                if let Some(profile_name) = profile {
                    config_loader = config_loader.profile_name(profile_name.clone());
                }
                let config = config_loader.load().await;
                Ok(S3Client::new(&config))
            }
            AwsCredentialsConfig::Explicit {
                access_key_id,
                secret_access_key,
                session_token,
            } => {
                let credentials = if let Some(token) = session_token {
                    Credentials::new(
                        access_key_id.clone(),
                        secret_access_key.clone(),
                        Some(token.clone()),
                        None,
                        "prism-explicit",
                    )
                } else {
                    Credentials::new(
                        access_key_id.clone(),
                        secret_access_key.clone(),
                        None,
                        None,
                        "prism-explicit",
                    )
                };

                let config = config_loader
                    .credentials_provider(SharedCredentialsProvider::new(credentials))
                    .load()
                    .await;

                Ok(S3Client::new(&config))
            }
            AwsCredentialsConfig::AssumeRole {
                role_arn,
                session_name,
                external_id,
                session_duration,
            } => {
                // First get base credentials
                let base_config = aws_config::defaults(BehaviorVersion::v2025_01_17())
                    .region(region.clone())
                    .load()
                    .await;

                let sts_client = aws_sdk_sts::Client::new(&base_config);

                let mut assume_role_request = sts_client
                    .assume_role()
                    .role_arn(role_arn.clone())
                    .role_session_name(session_name.clone())
                    .duration_seconds(session_duration.as_secs() as i32);

                if let Some(external_id) = external_id {
                    assume_role_request = assume_role_request.external_id(external_id);
                }

                let assume_role_response = assume_role_request.send().await.map_err(|e| {
                    AwsDaClientError::InitializationError(format!(
                        "Failed to assume role {}: {}",
                        role_arn, e
                    ))
                })?;

                let credentials = assume_role_response.credentials().ok_or_else(|| {
                    AwsDaClientError::InitializationError(
                        "No credentials returned from assume role".to_string(),
                    )
                })?;

                let aws_credentials = Credentials::new(
                    credentials.access_key_id(),
                    credentials.secret_access_key(),
                    Some(credentials.session_token().to_string()),
                    Some(credentials.expiration().to_owned().try_into().map_err(|e| {
                        AwsDaClientError::InitializationError(format!(
                            "Failed to convert expiration for role {}: {}",
                            role_arn, e
                        ))
                    })?),
                    "prism-assume-role",
                );

                let config = config_loader
                    .credentials_provider(SharedCredentialsProvider::new(aws_credentials))
                    .load()
                    .await;

                Ok(S3Client::new(&config))
            }
        }
    }

    /// Verifies that the S3 bucket is accessible with current credentials.
    async fn verify_bucket_access(client: &S3Client, bucket: &str) -> Result<(), AwsDaClientError> {
        debug!("Verifying access to S3 bucket '{}'", bucket);
        client.list_objects_v2().bucket(bucket).max_keys(1).send().await.map_err(|e| {
            AwsDaClientError::InitializationError(format!(
                "Cannot access S3 bucket '{}'. Check bucket exists and credentials have s3:ListBucket permission: {}",
                bucket, e
            ))
        })?;

        debug!("Verified access to S3 bucket '{}'", bucket);
        Ok(())
    }

    /// Verifies S3 bucket name according to AWS naming rules.
    fn verify_bucket_name(bucket_name: &str) -> Result<(), AwsDaClientError> {
        if bucket_name.len() < 3 || bucket_name.len() > 63 {
            return Err(AwsDaClientError::InitializationError(format!(
                "Bucket name '{}' must be between 3 and 63 characters",
                bucket_name
            )));
        }

        // Check if bucket name looks like an IP address first (before character validation)
        if bucket_name
            .split('.')
            .map(|part| part.parse::<u8>())
            .collect::<Result<Vec<_>, _>>()
            .is_ok()
            && bucket_name.split('.').count() == 4
        {
            return Err(AwsDaClientError::InitializationError(format!(
                "Bucket name '{}' cannot be formatted as an IP address",
                bucket_name
            )));
        }

        if !bucket_name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
            return Err(AwsDaClientError::InitializationError(format!(
                "Bucket name '{}' can only contain lowercase letters, numbers, and hyphens",
                bucket_name
            )));
        }

        if bucket_name.starts_with('-') || bucket_name.ends_with('-') {
            return Err(AwsDaClientError::InitializationError(format!(
                "Bucket name '{}' cannot start or end with a hyphen",
                bucket_name
            )));
        }

        if bucket_name.contains("--") {
            return Err(AwsDaClientError::InitializationError(format!(
                "Bucket name '{}' cannot contain consecutive hyphens",
                bucket_name
            )));
        }

        Ok(())
    }

    async fn verify_object_lock_enabled(
        client: &S3Client,
        bucket: &str,
    ) -> Result<(), AwsDaClientError> {
        match client.get_object_lock_configuration().bucket(bucket).send().await {
            Ok(response) => {
                if response.object_lock_configuration().is_some() {
                    debug!("Object Lock confirmed enabled for bucket '{}'", bucket);
                    Ok(())
                } else {
                    Err(AwsDaClientError::InitializationError(format!(
                        "Bucket '{}' exists but Object Lock is not enabled. WORM compliance requires Object Lock to be enabled at bucket creation.",
                        bucket
                    )))
                }
            }
            Err(e) => {
                let error_msg = e.to_string();
                if error_msg.contains("ObjectLockConfigurationNotFoundError") {
                    Err(AwsDaClientError::InitializationError(format!(
                        "Bucket '{}' does not have Object Lock enabled. For WORM compliance, Object Lock must be enabled when creating the bucket.",
                        bucket
                    )))
                } else {
                    Err(AwsDaClientError::InitializationError(format!(
                        "Cannot verify Object Lock configuration for bucket '{}': {}",
                        bucket, error_msg
                    )))
                }
            }
        }
    }

    /// Generic method to fetch and decode data from S3, handling `NoSuchKey` errors gracefully.
    async fn fetch_from_s3<T: FromBinary>(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<T>, AwsDaClientError> {
        trace!("Fetching from S3: bucket='{}', key='{}'", bucket, key);

        match self.s3_client.get_object().bucket(bucket).key(key).send().await {
            Ok(response) => {
                let body = response.body.collect().await.map_err(|e| {
                    AwsDaClientError::RequestFailed(format!("Failed to read S3 object body: {}", e))
                })?;

                let bytes = body.into_bytes();

                trace!("Downloaded {} bytes for key '{}'", bytes.len(), key);

                match T::decode_from_bytes(&bytes) {
                    Ok(decoded) => {
                        debug!("Successfully parsed data from S3 key '{}'", key);
                        Ok(Some(decoded))
                    }
                    Err(e) => {
                        warn!(
                            "Failed to parse data from S3 key '{}': {}. Data length: {} bytes",
                            key,
                            e,
                            bytes.len()
                        );
                        Ok(None)
                    }
                }
            }
            Err(e) => {
                // Check if this is a "not found" error
                let error_string = e.to_string();
                if error_string.contains("NoSuchKey") || error_string.contains("404") {
                    trace!("Key '{}' not found in bucket '{}'", key, bucket);
                    Ok(None)
                } else {
                    Err(AwsDaClientError::RequestFailed(format!(
                        "Failed to get object for key '{}' in bucket '{}': {}",
                        key, bucket, e
                    )))
                }
            }
        }
    }

    async fn fetch_all_from_s3<T: FromBinary>(
        &self,
        bucket: &str,
        prefix: &str,
    ) -> Result<Vec<T>, AwsDaClientError> {
        let objects = self.list_objects_with_prefix(bucket, prefix).await?;

        if objects.is_empty() {
            debug!("No objects found with prefix '{}'", prefix);
            return Ok(vec![]);
        }

        // Download and parse all objects
        let mut items = Vec::new();
        for object_key in objects {
            match self.fetch_from_s3(bucket, &object_key).await {
                Ok(Some(item)) => items.push(item),
                Ok(None) => {
                    warn!("Failed to parse item from object: {}", object_key);
                }
                Err(e) => {
                    warn!("Failed to download object {}: {}", object_key, e);
                }
            }
        }

        debug!("Retrieved {} items with prefix '{}'", items.len(), prefix);
        Ok(items)
    }

    /// Fetches metadata from S3, handling `NoSuchKey` errors gracefully.
    async fn fetch_metadata(&self) -> Result<Option<AwsDaMetaInfo>, AwsDaClientError> {
        let metadata_key = format!("{}metadata/info.json", self.key_prefix);
        self.fetch_from_s3(&self.metadata_bucket, &metadata_key).await
    }

    /// Submits metadata to S3 without WORM compliance.
    pub async fn submit_metadata(&self, metadata: AwsDaMetaInfo) -> Result<(), AwsDaClientError> {
        let metadata_key = format!("{}metadata/info.json", self.key_prefix);
        self.upload(&self.metadata_bucket, &metadata_key, metadata).await
    }

    /// Uploads metadata without WORM compliance settings.
    async fn upload<T: ToBinary>(
        &self,
        bucket: &str,
        key: &str,
        encodable: T,
    ) -> Result<(), AwsDaClientError> {
        let object_bytes = encodable.encode_to_bytes().map_err(|e| {
            AwsDaClientError::UploadFailed(format!("Failed to encode object: {}", e))
        })?;

        debug!(
            "Uploading object to S3: {}/{} ({} bytes)",
            bucket,
            key,
            object_bytes.len()
        );

        self.s3_client
            .put_object()
            .bucket(bucket)
            .key(key)
            .body(object_bytes.into())
            .send()
            .await
            .map_err(|e| {
                AwsDaClientError::UploadFailed(format!(
                    "Failed to upload object to S3 bucket '{}' with key '{}': {}",
                    bucket, key, e
                ))
            })?;

        debug!("Successfully uploaded object: {}/{}", bucket, key);
        Ok(())
    }

    /// Uploads data with WORM compliance settings.
    async fn upload_with_worm<T: ToBinary>(
        &self,
        bucket: &str,
        key: &str,
        encodable: T,
    ) -> Result<(), AwsDaClientError> {
        let retain_until = DateTime::from(
            SystemTime::now() + Duration::from_secs(self.retention_days as u64 * 24 * 3600),
        );
        let legal_hold_status = if self.enable_legal_holds {
            ObjectLockLegalHoldStatus::On
        } else {
            ObjectLockLegalHoldStatus::Off
        };

        let object_bytes = encodable.encode_to_bytes().map_err(|e| {
            AwsDaClientError::UploadFailed(format!("Failed to encode object: {}", e))
        })?;

        debug!(
            "Uploading object to S3: {}/{} ({} bytes)",
            bucket,
            key,
            object_bytes.len()
        );

        self.s3_client
            .put_object()
            .bucket(bucket)
            .key(key)
            .body(object_bytes.into())
            .object_lock_mode(ObjectLockMode::Compliance)
            .object_lock_retain_until_date(retain_until)
            .object_lock_legal_hold_status(legal_hold_status)
            .send()
            .await
            .map_err(|e| {
                AwsDaClientError::UploadFailed(format!(
                    "Failed to upload object to S3 bucket '{}' with key '{}': {}",
                    bucket, key, e
                ))
            })?;

        debug!(
            "Successfully uploaded object with WORM: {}/{} with {} day retention",
            bucket, key, self.retention_days
        );
        Ok(())
    }

    async fn list_objects_with_prefix(
        &self,
        bucket: &str,
        prefix: &str,
    ) -> Result<Vec<String>, AwsDaClientError> {
        let mut objects = Vec::new();
        let mut continuation_token: Option<String> = None;

        loop {
            let mut request = self.s3_client.list_objects_v2().bucket(bucket).prefix(prefix);

            if let Some(token) = continuation_token.as_ref() {
                request = request.continuation_token(token);
            }

            let response = request.send().await.map_err(|e| {
                AwsDaClientError::InitializationError(format!(
                    "Failed to list objects in bucket '{}' with prefix '{}': {}",
                    bucket, prefix, e
                ))
            })?;

            if let Some(contents) = &response.contents {
                for object in contents {
                    if let Some(key) = object.key() {
                        objects.push(key.to_string());
                    }
                }
            }

            if response.is_truncated() == Some(true) {
                continuation_token = response.next_continuation_token().map(|s| s.to_string());
            } else {
                break;
            }
        }

        trace!(
            "Listed {} objects from bucket '{}' with prefix '{}'",
            objects.len(),
            bucket,
            prefix
        );

        Ok(objects)
    }

    fn epoch_key(&self, height: u64, epoch_index: u64) -> String {
        let padded_height = format!("{:012}", height);
        format!(
            "{}epochs/{}/epoch_{}.bin",
            self.key_prefix, padded_height, epoch_index
        )
    }

    fn transaction_key(&self, height: u64, tx_index: u64) -> String {
        let padded_height = format!("{:012}", height);
        format!(
            "{}transactions/{}/tx_{}.bin",
            self.key_prefix, padded_height, tx_index
        )
    }
}
