//! AWS S3-based data availability layer implementation.
//!
//! This module provides data availability layer implementations using AWS S3
//! with WORM (Write Once Read Many) compliance through S3 Object Lock features.
//!
//! # Features
//!
//! - **WORM Compliance**: Automatic Object Lock with configurable retention periods
//! - **Light Client Support**: Efficient read-only access to finalized epochs
//! - **Full Node Support**: Complete read-write access to epochs and transactions
//! - **Cross-Region Replication**: Disaster recovery through automatic replication
//! - **Legal Holds**: Additional data protection beyond retention periods
//! - **Concurrent Operations**: Parallel uploads with configurable rate limiting
//!
//! # WORM Model Implementation
//!
//! The AWS implementation leverages S3 Object Lock to provide WORM capabilities:
//!
//! ## Object Lock Features
//! - **Compliance Mode**: Prevents object deletion/modification, even by root users
//! - **Retention Periods**: Configurable time-based protection (days to years)
//! - **Legal Holds**: Additional protection for litigation/compliance needs
//! - **Versioning**: Maintains complete audit trails of object changes
//!
//! ## Data Organization
//! ```text
//! bucket/
//! ├── epochs/
//! │   ├── 000000000001/epoch_0.bin    (epoch 0 at height 1)
//! │   ├── 000000000002/epoch_1.bin    (epoch 1 at height 1)
//! │   └── ...
//! ├── transactions/
//! │   ├── 000000000001/
//! │   │   ├── tx_0.bin         (transaction 0 at height 1)
//! │   │   ├── tx_1.bin         (transaction 1 at height 1)
//! │   │   └── ...
//! │   └── 000000000002/
//! │       ├── tx_0.bin         (transaction 0 at height 2)
//! │       └── ...
//! └── metadata/
//!     ├── info.json            (metadata for both things)
//! ```
//!
//! # Security Considerations
//!
//! ## IAM Permissions
//! The AWS credentials must have appropriate permissions:
//!
//! ### Light Client (Minimum)
//! ```json
//! {
//!   "Version": "2012-10-17",
//!   "Statement": [
//!     {
//!       "Effect": "Allow",
//!       "Action": [
//!         "s3:GetObject",
//!         "s3:ListBucket",
//!         "s3:GetObjectVersion"
//!       ],
//!       "Resource": [
//!         "arn:aws:s3:::your-epochs-bucket",
//!         "arn:aws:s3:::your-epochs-bucket/*"
//!       ]
//!     }
//!   ]
//! }
//! ```
//!
//! ### Full Node (Complete)
//! ```json
//! {
//!   "Version": "2012-10-17",
//!   "Statement": [
//!     {
//!       "Effect": "Allow",
//!       "Action": [
//!         "s3:GetObject",
//!         "s3:PutObject",
//!         "s3:ListBucket",
//!         "s3:GetObjectVersion",
//!         "s3:PutObjectRetention",
//!         "s3:PutObjectLegalHold",
//!         "s3:GetObjectLockConfiguration"
//!       ],
//!       "Resource": [
//!         "arn:aws:s3:::your-epochs-bucket",
//!         "arn:aws:s3:::your-epochs-bucket/*",
//!         "arn:aws:s3:::your-transactions-bucket",
//!         "arn:aws:s3:::your-transactions-bucket/*"
//!       ]
//!     }
//!   ]
//! }
//! ```
//!
//! # Usage Examples
//!
//! ## Light Client
//! ```rust,no_run
//! use prism_da::aws::{AwsLightDataAvailabilityLayer, AwsLightClientDAConfig};
//! use prism_da::LightDataAvailabilityLayer;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = AwsLightClientDAConfig::default();
//!     let da = AwsLightDataAvailabilityLayer::new(&config).await?;
//!
//!     let epochs = da.get_finalized_epochs(100).await?;
//!     println!("Found {} epochs at height 100", epochs.len());
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Full Node
//! ```rust,no_run
//! use prism_da::aws::{AwsFullNodeDataAvailabilityLayer, AwsFullNodeDAConfig};
//! use prism_da::{DataAvailabilityLayer, LightDataAvailabilityLayer};
//! use prism_common::transaction::Transaction;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = AwsFullNodeDAConfig::default();
//!     let da = AwsFullNodeDataAvailabilityLayer::new(&config).await?;
//!
//!     da.start().await?;
//!
//!     let transactions = vec![/* your transactions */];
//!     let height = da.submit_transactions(transactions).await?;
//!     println!("Published at height: {}", height);
//!
//!     Ok(())
//! }
//! ```

pub mod client;
pub mod config;
#[cfg(not(target_arch = "wasm32"))]
pub mod full_node;
pub mod light_client;

pub use config::{
    AwsCredentialsConfig, AwsLightClientDAConfig, DEFAULT_AWS_REGION, DEFAULT_RETENTION_DAYS,
    DEFAULT_S3_MAX_RETRIES, DEFAULT_S3_MAX_TIMEOUT,
};

#[cfg(not(target_arch = "wasm32"))]
pub use config::AwsFullNodeDAConfig;

#[cfg(not(target_arch = "wasm32"))]
pub use full_node::AwsFullNodeDataAvailabilityLayer;

pub use light_client::AwsLightDataAvailabilityLayer;
