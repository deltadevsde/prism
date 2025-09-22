use serde::{Deserialize, Serialize};
use serde_with::{DurationSeconds, serde_as};
use std::time::Duration;

/// Default S3 region for AWS operations
pub const DEFAULT_AWS_REGION: &str = "us-east-1";

/// Default timeout for S3 operations
pub const DEFAULT_S3_MAX_TIMEOUT: Duration = Duration::from_secs(30);

/// Default maximum retries for S3 operations
pub const DEFAULT_S3_MAX_RETRIES: u32 = 3;

/// Default retention period for WORM compliance (30 days)
pub const DEFAULT_RETENTION_DAYS: u32 = 30;

/// Configuration for AWS S3-based data availability layer used by light clients.
///
/// Light clients provide read-only access to finalized epochs stored in S3
/// with WORM (Write Once Read Many) guarantees for data integrity.
///
/// # AWS S3 WORM Model
///
/// This implementation leverages AWS S3 Object Lock to provide WORM capabilities:
/// - **Compliance Mode**: Prevents deletion or modification of objects
/// - **Retention Periods**: Automatically enforced immutability windows
/// - **Legal Holds**: Additional protection for critical data
/// - **Versioning**: Maintains object history for audit trails
///
/// # Bucket Requirements
///
/// The S3 bucket must be configured with:
/// - Object Lock enabled at bucket creation
/// - Versioning enabled (required for Object Lock)
/// - Appropriate IAM permissions for the credentials
/// - Cross-region replication (recommended for high availability)
///
/// # Data Organization
///
/// Objects are stored with the following key structure:
/// - Epochs: `epochs/{height}/epoch.bin`
/// - Transactions: `transactions/{height}/tx_{index}.bin`
/// - Metadata: `metadata/{type}/{height}/info.json`
///
/// This structure enables efficient queries by height and supports
/// parallel processing of multiple transactions per block.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AwsLightClientDAConfig {
    /// AWS region for S3 operations.
    ///
    /// Choose a region close to your application for optimal latency.
    /// Common regions:
    /// - `us-east-1`: US East (N. Virginia) - Default, lowest latency from many locations
    /// - `us-west-2`: US West (Oregon) - Good for west coast applications
    /// - `eu-west-1`: Europe (Ireland) - Good for European applications
    /// - `ap-northeast-1`: Asia Pacific (Tokyo) - Good for Asian applications
    pub region: String,

    /// AWS endpoint for S3 operations.
    ///
    /// Use this if you need to connect to a custom S3-compatible service.
    /// Leave empty to use the default AWS S3 endpoint.
    pub endpoint: Option<String>,

    /// S3 bucket name for storing finalized epochs.
    ///
    /// Must be a globally unique bucket name that follows S3 naming conventions:
    /// - 3-63 characters long
    /// - Lowercase letters, numbers, and hyphens only
    /// - Must start and end with lowercase letter or number
    /// - No consecutive hyphens or periods
    ///
    /// Example: "prism-epochs-production-us-east-1"
    ///
    /// **Security Note**: Use separate buckets for different environments
    /// (dev, staging, production) to prevent accidental cross-environment access.
    pub epochs_bucket: String,

    /// S3 bucket name for storing metadata.
    ///
    /// Must be a globally unique bucket name that follows S3 naming conventions:
    /// - 3-63 characters long
    /// - Lowercase letters, numbers, and hyphens only
    /// - Must start and end with lowercase letter or number
    /// - No consecutive hyphens or periods
    ///
    /// Example: "prism-metadata-production-us-east-1"
    ///
    /// **Security Note**: Use separate buckets for different environments
    /// (dev, staging, production) to prevent accidental cross-environment access.
    pub metadata_bucket: String,

    /// Timeout duration for S3 operations.
    ///
    /// This timeout applies to individual S3 API calls including:
    /// - `GetObject` requests for reading epochs and transactions
    /// - `ListObjects` requests for discovering available data
    /// - `HeadObject` requests for checking object metadata
    ///
    /// Consider your network conditions and object sizes when setting this value:
    /// - Local/fast networks: 10-30 seconds
    /// - Slower networks: 60-120 seconds
    /// - Large objects: Scale with expected transfer time
    #[serde_as(as = "DurationSeconds<u64>")]
    pub max_timeout: Duration,

    /// Maximum number of retry attempts for failed S3 operations.
    ///
    /// AWS SDK handles exponential backoff automatically, but you can control
    /// the maximum number of attempts. Higher values provide better reliability
    /// during transient network issues but may increase latency.
    ///
    /// Recommended values:
    /// - Production: 3-5 retries
    /// - Development: 1-2 retries
    /// - CI/Testing: 1 retry to fail fast
    pub max_retries: u32,

    /// AWS credentials configuration.
    ///
    /// Determines how the client authenticates with AWS services.
    /// The SDK will automatically discover credentials in the following order:
    /// 1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
    /// 2. AWS credentials file (~/.aws/credentials)
    /// 3. IAM instance profile (for EC2 instances)
    /// 4. IAM role for service accounts (for EKS/Kubernetes)
    /// 5. AWS STS assume role
    pub credentials: AwsCredentialsConfig,

    /// Optional key prefix for organizing data within buckets.
    ///
    /// Useful for:
    /// - Multi-tenant deployments: `tenant-{id}/`
    /// - Environment separation: `prod/`, `staging/`, `dev/`
    /// - Network separation: `mainnet/`, `testnet/`
    ///
    /// If specified, all object keys will be prefixed with this value.
    /// Must end with '/' if you want directory-style organization.
    ///
    /// Example: "mainnet/" results in keys like "mainnet/epochs/123/epoch.bin"
    ///
    /// Default: ""
    pub key_prefix: String,

    #[serde_as(as = "DurationSeconds<u64>")]
    pub block_time: Duration,
}

impl Default for AwsLightClientDAConfig {
    fn default() -> Self {
        Self {
            region: DEFAULT_AWS_REGION.to_string(),
            endpoint: None,
            epochs_bucket: "prism-epochs".to_string(),
            metadata_bucket: "prism-metadata".to_string(),
            max_timeout: DEFAULT_S3_MAX_TIMEOUT,
            max_retries: DEFAULT_S3_MAX_RETRIES,
            credentials: AwsCredentialsConfig::default(),
            key_prefix: String::new(),
            block_time: Duration::from_secs(10),
        }
    }
}

/// Configuration for AWS S3-based data availability layer used by full nodes.
///
/// Full nodes provide read-write access to both finalized epochs and transaction data
/// with WORM compliance for published data. This configuration extends the light client
/// configuration with additional capabilities for data publishing and management.
///
/// # Publishing Workflow
///
/// Full nodes follow this workflow for publishing data:
/// 1. **Upload**: Write objects to S3 with temporary keys
/// 2. **Verify**: Confirm successful upload and data integrity
/// 3. **Lock**: Apply Object Lock with retention period for WORM compliance
/// 4. **Notify**: Broadcast availability to network participants
///
/// # WORM Compliance Features
///
/// - **Retention Periods**: Automatic protection against deletion/modification
/// - **Legal Holds**: Additional protection for compliance requirements
/// - **Audit Trails**: Complete history of object access and modifications
/// - **Cross-Region Replication**: Geographic data distribution for availability
#[cfg(not(target_arch = "wasm32"))]
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AwsFullNodeDAConfig {
    /// Light client configuration (inherited).
    ///
    /// Full nodes include all light client capabilities plus additional
    /// features for data publishing and management.
    #[serde(flatten)]
    pub light_client: AwsLightClientDAConfig,

    /// S3 bucket name for storing transaction data.
    ///
    /// Must follow the same naming conventions as `epochs_bucket`.
    ///
    /// Example: "prism-transactions-production-us-east-1"
    pub transactions_bucket: String,

    /// WORM retention period in days.
    ///
    /// Once objects are uploaded, they cannot be deleted or modified
    /// for this duration. This provides immutability guarantees required
    /// for blockchain data integrity.
    ///
    /// Considerations:
    /// - **Legal Requirements**: Some jurisdictions require specific retention periods
    /// - **Storage Costs**: Longer periods increase storage costs
    /// - **Data Lifecycle**: Align with your data archival policies
    ///
    /// Recommended values:
    /// - Development: 1-7 days
    /// - Testing: 7-30 days
    /// - Production: 30-365 days (or more for compliance)
    pub retention_days: u32,

    /// Enable legal hold feature for critical data protection.
    ///
    /// When enabled, objects can have additional legal hold protection
    /// beyond the retention period. Legal holds:
    /// - Override retention periods (objects protected until hold is removed)
    /// - Useful for litigation, audits, or regulatory requirements
    /// - Can be applied/removed independently of retention periods
    /// - Provide additional layer of data protection
    ///
    /// **Note**: Legal holds may incur additional storage costs and
    /// require specific IAM permissions to manage.
    pub enable_legal_holds: bool,

    /// Enable cross-region replication for high availability.
    ///
    /// When enabled, data is automatically replicated to a secondary region:
    /// - **Disaster Recovery**: Protects against regional outages
    /// - **Performance**: Allows reads from geographically closer regions
    /// - **Compliance**: Satisfies data residency requirements
    ///
    /// **Requirements**:
    /// - Destination bucket must exist in target region
    /// - Cross-region replication IAM role must be configured
    /// - Additional costs for cross-region transfer and storage
    pub enable_cross_region_replication: bool,

    /// Target region for cross-region replication.
    ///
    /// Only used when `enable_cross_region_replication` is true.
    /// Should be different from the primary region for effective
    /// disaster recovery coverage.
    ///
    /// Consider:
    /// - **Geographic Distance**: Choose regions far apart for disaster recovery
    /// - **Latency**: Balance distance with application performance needs
    /// - **Compliance**: Ensure target region meets regulatory requirements
    /// - **Costs**: Different regions have different pricing
    pub replication_region: Option<String>,

    /// Maximum concurrent uploads for batch operations.
    ///
    /// When publishing multiple objects (e.g., transaction batches),
    /// this limits the number of simultaneous S3 uploads to:
    /// - Prevent overwhelming S3 service limits
    /// - Control bandwidth usage
    /// - Manage memory usage for large batches
    ///
    /// AWS S3 limits:
    /// - 3,500 PUT requests per second per prefix
    /// - Consider your key naming strategy when setting this value
    ///
    /// Recommended values:
    /// - Small instances: 5-10
    /// - Medium instances: 10-25
    /// - Large instances: 25-50
    pub max_concurrent_uploads: u32,
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for AwsFullNodeDAConfig {
    fn default() -> Self {
        Self {
            light_client: AwsLightClientDAConfig::default(),
            transactions_bucket: "prism-transactions".to_string(),
            retention_days: DEFAULT_RETENTION_DAYS,
            enable_legal_holds: false,
            enable_cross_region_replication: false,
            replication_region: None,
            max_concurrent_uploads: 10,
        }
    }
}

/// AWS credentials configuration options.
///
/// Provides flexible authentication methods for different deployment scenarios.
/// The AWS SDK will attempt authentication in a specific order, and this
/// configuration allows you to control or override that behavior.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AwsCredentialsConfig {
    /// Use AWS SDK's default credential provider chain.
    ///
    /// This is the recommended approach for most deployments as it follows
    /// AWS best practices and works across different environments:
    ///
    /// 1. **Environment Variables**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
    ///    `AWS_SESSION_TOKEN`
    /// 2. **AWS Credentials File**: ~/.aws/credentials (with optional profile)
    /// 3. **IAM Instance Profile**: For EC2 instances
    /// 4. **IAM Roles for Service Accounts**: For EKS/Kubernetes
    /// 5. **AWS STS Assume Role**: For cross-account access
    ///
    /// This method is secure, flexible, and follows AWS security best practices.
    Default {
        /// Optional AWS profile name to use from credentials file.
        ///
        /// If not specified, uses the default profile.
        /// Useful for:
        /// - Development environments with multiple AWS accounts
        /// - Role-based access in shared environments
        /// - Testing with different permission sets
        profile: Option<String>,
    },

    /// Use explicit access keys (NOT RECOMMENDED for production).
    ///
    /// **Security Warning**: This method stores credentials in configuration
    /// files, which poses security risks:
    /// - Credentials may be logged or exposed in version control
    /// - No automatic credential rotation
    /// - Difficult to manage across multiple environments
    ///
    /// Only use this for:
    /// - Local development and testing
    /// - Environments where IAM roles are not available
    /// - Temporary setups or proof-of-concepts
    ///
    /// **Better Alternatives**:
    /// - Use environment variables instead of config files
    /// - Use IAM roles when running on AWS infrastructure
    /// - Use AWS SSO for development environments
    Explicit {
        /// AWS access key ID.
        access_key_id: String,

        /// AWS secret access key.
        secret_access_key: String,

        /// Optional session token for temporary credentials.
        session_token: Option<String>,
    },
    /// Use AWS STS to assume a specific IAM role.
    ///
    /// Useful for:
    /// - Cross-account access patterns
    /// - Temporary elevated permissions
    /// - Service-to-service authentication
    /// - Multi-tenant applications with role-based access
    ///
    /// **Requirements**:
    /// - The role must trust the principal making the assume role call
    /// - Appropriate permissions must be configured on the role
    /// - MFA may be required depending on role trust policy
    AssumeRole {
        /// ARN of the IAM role to assume.
        ///
        /// Format: `arn:aws:iam::ACCOUNT-ID:role/ROLE-NAME`
        /// Example: `arn:aws:iam::123456789012:role/PrismDataAccess`
        role_arn: String,

        /// Session name for the assumed role session.
        ///
        /// This appears in `CloudTrail` logs and can be used for:
        /// - Auditing and tracking access
        /// - Identifying specific application instances
        /// - Debugging authentication issues
        ///
        /// Must be 2-64 characters, alphanumeric and +=,.@-_
        session_name: String,

        /// Optional external ID for additional security.
        ///
        /// Used to prevent the "confused deputy" problem in cross-account scenarios.
        /// Should be a unique, hard-to-guess value shared between accounts.
        external_id: Option<String>,

        /// Duration of the assumed role session (in seconds).
        ///
        /// AWS limits:
        /// - Minimum: 900 seconds (15 minutes)
        /// - Maximum: Depends on role's maximum session duration setting
        /// - Default: 3600 seconds (1 hour)
        ///
        /// Consider your application's runtime and security requirements.
        #[serde_as(as = "DurationSeconds<u64>")]
        session_duration: Duration,
    },
}

impl Default for AwsCredentialsConfig {
    fn default() -> Self {
        Self::Default { profile: None }
    }
}

impl AwsCredentialsConfig {
    /// Create credentials config for development with explicit keys.
    ///
    /// **WARNING**: Only use for local development. Never commit credentials to version control.
    pub const fn development(access_key_id: String, secret_access_key: String) -> Self {
        Self::Explicit {
            access_key_id,
            secret_access_key,
            session_token: None,
        }
    }

    /// Create credentials config for cross-account access.
    pub const fn cross_account(role_arn: String, session_name: String) -> Self {
        Self::AssumeRole {
            role_arn,
            session_name,
            external_id: None,
            session_duration: Duration::from_secs(3600), // 1 hour default
        }
    }

    /// Create credentials config with specific AWS profile.
    pub const fn profile(profile_name: String) -> Self {
        Self::Default {
            profile: Some(profile_name),
        }
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::aws::{AwsCredentialsConfig, AwsLightClientDAConfig};

    #[cfg(not(target_arch = "wasm32"))]
    use crate::aws::AwsFullNodeDAConfig;

    fn create_test_light_client_config() -> AwsLightClientDAConfig {
        AwsLightClientDAConfig {
            region: "us-east-1".to_string(),
            endpoint: None,
            epochs_bucket: "test-epochs-bucket".to_string(),
            metadata_bucket: "test-metadata-bucket".to_string(),
            max_timeout: std::time::Duration::from_secs(30),
            max_retries: 1,
            credentials: AwsCredentialsConfig::development(
                "test_access_key".to_string(),
                "test_secret_key".to_string(),
            ),
            key_prefix: String::new(),
            block_time: Duration::from_secs(1), // Shorter for tests
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn create_test_full_node_config() -> AwsFullNodeDAConfig {
        AwsFullNodeDAConfig {
            light_client: AwsLightClientDAConfig {
                region: "us-east-1".to_string(),
                endpoint: None,
                epochs_bucket: "test-epochs-bucket".to_string(),
                max_timeout: std::time::Duration::from_secs(30),
                max_retries: 1,
                credentials: AwsCredentialsConfig::development(
                    "test_access_key".to_string(),
                    "test_secret_key".to_string(),
                ),
                key_prefix: String::new(),
                metadata_bucket: "test-metadata-bucket".to_string(),
                block_time: Duration::from_secs(1), // Shorter for tests
            },
            transactions_bucket: "test-transactions-bucket".to_string(),
            retention_days: 30,
            enable_legal_holds: false,
            enable_cross_region_replication: false,
            replication_region: None,
            max_concurrent_uploads: 5,
        }
    }

    #[test]
    fn test_light_client_config_structure() {
        let config = create_test_light_client_config();

        assert_eq!(config.region, "us-east-1");
        assert_eq!(config.epochs_bucket, "test-epochs-bucket");
        assert_eq!(config.metadata_bucket, "test-metadata-bucket");
        assert_eq!(config.max_timeout, Duration::from_secs(30));
        assert_eq!(config.max_retries, 1);
        assert_eq!(config.block_time, Duration::from_secs(1));
        assert!(config.key_prefix.is_empty());
        assert!(config.endpoint.is_none());
    }

    #[test]
    fn test_light_client_config_with_custom_endpoint() {
        let mut config = create_test_light_client_config();
        config.endpoint = Some("http://localhost:9000".to_string());

        assert_eq!(config.endpoint, Some("http://localhost:9000".to_string()));
    }

    #[test]
    fn test_light_client_config_with_key_prefix() {
        let mut config = create_test_light_client_config();
        config.key_prefix = "test/prefix/".to_string();

        assert_eq!(config.key_prefix, "test/prefix/");
    }

    #[test]
    fn test_light_client_config_with_different_credentials() {
        let mut config = create_test_light_client_config();

        // Test explicit credentials
        config.credentials = AwsCredentialsConfig::development(
            "different_key".to_string(),
            "different_secret".to_string(),
        );

        match config.credentials {
            AwsCredentialsConfig::Explicit {
                access_key_id,
                secret_access_key,
                ..
            } => {
                assert_eq!(access_key_id, "different_key");
                assert_eq!(secret_access_key, "different_secret");
            }
            _ => panic!("Expected explicit credentials"),
        }
    }

    #[test]
    fn test_light_client_config_timeout_and_retries() {
        let mut config = create_test_light_client_config();

        // Test different timeout values
        config.max_timeout = Duration::from_secs(60);
        assert_eq!(config.max_timeout, Duration::from_secs(60));

        config.max_timeout = Duration::from_millis(5000);
        assert_eq!(config.max_timeout, Duration::from_millis(5000));

        // Test different retry values
        config.max_retries = 5;
        assert_eq!(config.max_retries, 5);

        config.max_retries = 0;
        assert_eq!(config.max_retries, 0);
    }

    #[test]
    fn test_light_client_block_time_configuration() {
        let mut config = create_test_light_client_config();

        // Test different block time values
        config.block_time = Duration::from_millis(100);
        assert_eq!(config.block_time, Duration::from_millis(100));

        config.block_time = Duration::from_secs(30);
        assert_eq!(config.block_time, Duration::from_secs(30));

        config.block_time = Duration::from_millis(500);
        assert_eq!(config.block_time, Duration::from_millis(500));
    }

    #[test]
    fn test_light_client_bucket_configuration() {
        let mut config = create_test_light_client_config();

        // Test different bucket names
        config.epochs_bucket = "production-epochs".to_string();
        config.metadata_bucket = "production-metadata".to_string();

        assert_eq!(config.epochs_bucket, "production-epochs");
        assert_eq!(config.metadata_bucket, "production-metadata");

        // Test with environment-specific bucket names
        config.epochs_bucket = "dev-prism-epochs-us-east-1".to_string();
        config.metadata_bucket = "dev-prism-metadata-us-east-1".to_string();

        assert_eq!(config.epochs_bucket, "dev-prism-epochs-us-east-1");
        assert_eq!(config.metadata_bucket, "dev-prism-metadata-us-east-1");
    }

    #[test]
    fn test_light_client_region_configuration() {
        let mut config = create_test_light_client_config();

        // Test different AWS regions
        let regions = vec![
            "us-west-1",
            "us-west-2",
            "eu-west-1",
            "eu-central-1",
            "ap-southeast-1",
        ];

        for region in regions {
            config.region = region.to_string();
            assert_eq!(config.region, region);
        }
    }

    #[test]
    fn test_credentials_variants() {
        let config = create_test_light_client_config();

        // Test that development credentials are properly constructed
        match config.credentials {
            AwsCredentialsConfig::Explicit {
                access_key_id,
                secret_access_key,
                session_token,
            } => {
                assert_eq!(access_key_id, "test_access_key");
                assert_eq!(secret_access_key, "test_secret_key");
                assert!(session_token.is_none());
            }
            _ => panic!("Expected explicit credentials for development config"),
        }

        // Test default credentials
        let default_creds = AwsCredentialsConfig::default();
        match default_creds {
            AwsCredentialsConfig::Default { profile } => {
                assert!(profile.is_none());
            }
            _ => panic!("Expected default credentials"),
        }

        // Test profile-based credentials
        let profile_creds = AwsCredentialsConfig::profile("test-profile".to_string());
        match profile_creds {
            AwsCredentialsConfig::Default { profile } => {
                assert_eq!(profile, Some("test-profile".to_string()));
            }
            _ => panic!("Expected profile-based credentials"),
        }
    }

    // Full node config tests
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_full_node_config_structure() {
        let config = create_test_full_node_config();

        assert_eq!(config.retention_days, 30);
        assert!(!config.enable_legal_holds);
        assert!(!config.enable_cross_region_replication);
        assert_eq!(config.max_concurrent_uploads, 5);
        assert_eq!(config.light_client.epochs_bucket, "test-epochs-bucket");
        assert_eq!(config.transactions_bucket, "test-transactions-bucket");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_full_node_config_with_replication() {
        let mut config = create_test_full_node_config();
        config.enable_cross_region_replication = true;
        config.replication_region = Some("us-west-2".to_string());

        assert!(config.enable_cross_region_replication);
        assert_eq!(config.replication_region, Some("us-west-2".to_string()));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_full_node_config_with_legal_holds() {
        let mut config = create_test_full_node_config();
        config.enable_legal_holds = true;

        assert!(config.enable_legal_holds);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_full_node_worm_features_config() {
        let config = create_test_full_node_config();

        // Test WORM-related configuration
        assert_eq!(config.retention_days, 30);
        assert!(!config.enable_legal_holds);

        // Test with different retention periods
        let mut long_retention_config = config.clone();
        long_retention_config.retention_days = 365;
        assert_eq!(long_retention_config.retention_days, 365);

        // Test with legal holds enabled
        let mut legal_hold_config = config;
        legal_hold_config.enable_legal_holds = true;
        assert!(legal_hold_config.enable_legal_holds);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_full_node_concurrent_upload_config() {
        let mut config = create_test_full_node_config();

        // Test default concurrent uploads
        assert_eq!(config.max_concurrent_uploads, 5);

        // Test different values
        config.max_concurrent_uploads = 10;
        assert_eq!(config.max_concurrent_uploads, 10);

        config.max_concurrent_uploads = 1;
        assert_eq!(config.max_concurrent_uploads, 1);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_full_node_block_time_configuration() {
        let mut config = create_test_full_node_config();

        // Test default block time (set to 1 second for tests)
        assert_eq!(config.light_client.block_time, Duration::from_secs(1));

        // Test different block times
        config.light_client.block_time = Duration::from_millis(500);
        assert_eq!(config.light_client.block_time, Duration::from_millis(500));

        config.light_client.block_time = Duration::from_secs(12);
        assert_eq!(config.light_client.block_time, Duration::from_secs(12));
    }
}
