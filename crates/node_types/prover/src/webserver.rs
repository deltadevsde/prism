use crate::Prover;
use anyhow::{bail, Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use jmt::proof::{SparseMerkleNode, SparseMerkleProof};
use prism_common::{
    account::Account, digest::Digest, operation::Operation, transaction::Transaction,
};
use prism_keys::{Signature, VerifyingKey};
use prism_tree::{
    hasher::TreeHasher,
    proofs::{Proof, UpdateProof},
    AccountResponse,
};
use serde::{Deserialize, Serialize};
use std::{self, sync::Arc};
use tower_http::cors::CorsLayer;
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebServerConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
}

impl Default for WebServerConfig {
    fn default() -> Self {
        WebServerConfig {
            enabled: true,
            host: "127.0.0.1".to_string(),
            port: 0,
        }
    }
}

pub struct WebServer {
    pub cfg: WebServerConfig,
    pub session: Arc<Prover>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct EpochData {
    epoch_number: u64,
    previous_commitment: String,
    current_commitment: String,
    proofs: Vec<Proof>,
}

#[derive(Deserialize, Debug, ToSchema)]
pub struct TransactionRequest {
    pub id: String,
    pub operation: Operation,
    pub nonce: u64,
    pub signature: Signature,
    pub vk: VerifyingKey,
}

impl From<TransactionRequest> for Transaction {
    fn from(tx: TransactionRequest) -> Self {
        Transaction {
            id: tx.id,
            operation: tx.operation,
            nonce: tx.nonce,
            signature: tx.signature,
            vk: tx.vk,
        }
    }
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct UpdateProofResponse(UpdateProof);

#[derive(Serialize, Deserialize, ToSchema)]
pub struct Hash(Digest);

#[derive(Serialize, Deserialize, ToSchema)]
pub struct UserKeyRequest {
    pub id: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct UserKeyResponse {
    pub account: Option<Account>,
    pub proof: JmtProofResponse,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct JmtProofResponse {
    pub leaf: Option<Digest>,
    pub siblings: Vec<Digest>,
}

impl From<SparseMerkleProof<TreeHasher>> for JmtProofResponse {
    fn from(proof: SparseMerkleProof<TreeHasher>) -> Self {
        let leaf_hash = proof.leaf().map(|node| node.hash::<TreeHasher>()).map(Digest::new);
        let sibling_hashes = proof
            .siblings()
            .iter()
            .map(SparseMerkleNode::hash::<TreeHasher>)
            .map(Digest::new)
            .collect();
        Self {
            leaf: leaf_hash,
            siblings: sibling_hashes,
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(post_transaction, get_account, get_commitment),
    components(schemas(
        TransactionRequest,
        EpochData,
        UpdateProofResponse,
        Hash,
        UserKeyRequest,
        UserKeyResponse,
        JmtProofResponse
    ))
)]
struct ApiDoc;

impl WebServer {
    pub fn new(cfg: WebServerConfig, session: Arc<Prover>) -> Self {
        Self { cfg, session }
    }

    pub async fn start(&self) -> Result<()> {
        if !self.cfg.enabled {
            bail!("Webserver is disabled")
        }

        let app = Router::new()
            .route("/transaction", post(post_transaction))
            .route("/get-account", post(get_account))
            .route("/get-current-commitment", get(get_commitment))
            .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
            .layer(CorsLayer::permissive())
            .with_state(self.session.clone());

        let addr = format!("{}:{}", self.cfg.host, self.cfg.port);
        let server = axum::Server::bind(&addr.parse().unwrap()).serve(app.into_make_service());

        let socket_addr = server.local_addr();
        info!(
            "Starting webserver on {}:{}",
            self.cfg.host,
            socket_addr.port()
        );

        server.await.context("Server error")?;

        Ok(())
    }
}

/// Updates or inserts a transaction in the transparency dictionary, pending inclusion in the next epoch.
///
#[utoipa::path(
    post,
    path = "/transaction",
    request_body = TransactionRequest,
    responses(
        (status = 200, description = "Entry update queued for insertion into next epoch"),
        (status = 400, description = "Bad request"),
        (status = 500, description = "Internal server error")
    )
)]
async fn post_transaction(
    State(session): State<Arc<Prover>>,
    Json(tx_request): Json<TransactionRequest>,
) -> impl IntoResponse {
    match session.validate_and_queue_update(tx_request.into()).await {
        Ok(_) => (
            StatusCode::OK,
            "Entry update queued for insertion into next epoch",
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            format!("Could not update entry: {}", e),
        )
            .into_response(),
    }
}

/// The /get-account endpoint returns all added keys for a given user id.
///
/// If the ID is not found in the database, the endpoint will return a 400 response with the message "Could not calculate values".
///
#[utoipa::path(
    post,
    path = "/get-account",
    request_body = UserKeyRequest,
    responses(
        (status = 200, description = "Successfully retrieved valid keys", body = UpdateKeyResponse),
        (status = 400, description = "Bad request")
    )
)]
async fn get_account(
    State(session): State<Arc<Prover>>,
    Json(request): Json<UserKeyRequest>,
) -> impl IntoResponse {
    let get_account_result = session.get_account(&request.id).await;
    let Ok(account_response) = get_account_result else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "Failed to retrieve account or non-membership-proof: {}",
                get_account_result.unwrap_err()
            ),
        )
            .into_response();
    };

    match account_response {
        AccountResponse::Found(account, membership_proof) => (
            StatusCode::OK,
            Json(UserKeyResponse {
                account: Some(*account),
                proof: JmtProofResponse::from(membership_proof.proof),
            }),
        )
            .into_response(),
        AccountResponse::NotFound(non_membership_proof) => (
            StatusCode::OK,
            Json(UserKeyResponse {
                account: None,
                proof: JmtProofResponse::from(non_membership_proof.proof),
            }),
        )
            .into_response(),
    }
}

/// Returns the commitment (tree root) of the IndexedMerkleTree initialized from the database.
///
#[utoipa::path(
    get,
    path = "/get-current-commitment",
    responses(
        (status = 200, description = "Successfully retrieved current commitment", body = Hash),
        (status = 500, description = "Internal server error")
    )
)]
async fn get_commitment(State(session): State<Arc<Prover>>) -> impl IntoResponse {
    match session.get_commitment().await {
        Ok(commitment) => (StatusCode::OK, Json(commitment)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
