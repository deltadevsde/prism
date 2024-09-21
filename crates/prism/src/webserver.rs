use crate::{cfg::WebServerConfig, node_types::sequencer::Sequencer};
use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use indexed_merkle_tree::{
    tree::{Proof, UpdateProof},
    Hash as TreeHash,
};
use prism_common::{hashchain::Hashchain, operation::Operation};
use serde::{Deserialize, Serialize};
use std::{self, sync::Arc};
use tower_http::cors::CorsLayer;
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

pub struct WebServer {
    pub cfg: WebServerConfig,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct EpochData {
    epoch_number: u64,
    previous_commitment: String,
    current_commitment: String,
    proofs: Vec<Proof>,
}

#[derive(Deserialize, Debug, ToSchema)]
pub struct OperationInput {
    pub operation: Operation,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct UpdateProofResponse(UpdateProof);

#[derive(Serialize, Deserialize, ToSchema)]
pub struct Hash(TreeHash);

#[derive(Serialize, Deserialize, ToSchema)]
pub struct UserKeyRequest {
    pub id: String,
}

// TODO: Retrieve Merkle proof of current epoch
#[derive(Serialize, Deserialize, ToSchema)]
pub struct UserKeyResponse {
    pub hashchain: Hashchain,
    // pub proof: MerkleProof
}

#[derive(OpenApi)]
#[openapi(
    paths(update_entry, get_hashchain, get_commitment),
    components(schemas(
        OperationInput,
        EpochData,
        UpdateProofResponse,
        Hash,
        UserKeyRequest,
        UserKeyResponse
    ))
)]
struct ApiDoc;

impl WebServer {
    pub fn new(cfg: WebServerConfig) -> Self {
        Self { cfg }
    }

    pub async fn start(&self, session: Arc<Sequencer>) -> Result<()> {
        info!("starting webserver on {}:{}", self.cfg.host, self.cfg.port);
        let app = Router::new()
            .route("/update-entry", post(update_entry))
            .route("/get-hashchain", post(get_hashchain))
            .route("/get-current-commitment", get(get_commitment))
            .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
            .layer(CorsLayer::permissive())
            .with_state(session);

        let addr = format!("{}:{}", self.cfg.host, self.cfg.port);
        axum::Server::bind(&addr.parse().unwrap())
            .serve(app.into_make_service())
            .await
            .context("Server error")?;

        Ok(())
    }
}

/// Updates or inserts an entry in the transparency dictionary, pending inclusion in the next epoch.
///
#[utoipa::path(
    post,
    path = "/update-entry",
    request_body = UpdateEntryJson,
    responses(
        (status = 200, description = "Entry update queued for insertion into next epoch"),
        (status = 400, description = "Bad request"),
        (status = 500, description = "Internal server error")
    )
)]
async fn update_entry(
    State(session): State<Arc<Sequencer>>,
    Json(operation_input): Json<OperationInput>,
) -> impl IntoResponse {
    match session
        .validate_and_queue_update(&operation_input.operation)
        .await
    {
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

/// The /get-hashchain endpoint returns all added keys for a given user id.
///
/// If the ID is not found in the database, the endpoint will return a 400 response with the message "Could not calculate values".
///
#[utoipa::path(
    post,
    path = "/get-hashchain",
    request_body = UserKeyRequest,
    responses(
        (status = 200, description = "Successfully retrieved valid keys", body = UpdateKeyResponse),
        (status = 400, description = "Bad request")
    )
)]
async fn get_hashchain(
    State(session): State<Arc<Sequencer>>,
    Json(request): Json<UserKeyRequest>,
) -> impl IntoResponse {
    match session.get_hashchain(&request.id).await {
        Ok(hashchain_or_proof) => match hashchain_or_proof {
            Ok(hashchain) => (StatusCode::OK, Json(UserKeyResponse { hashchain })).into_response(),
            Err(non_inclusion_proof) => {
                (StatusCode::BAD_REQUEST, Json(non_inclusion_proof)).into_response()
            }
        },
        Err(err) => (
            StatusCode::BAD_REQUEST,
            format!("Couldn't get hashchain: {}", err),
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
async fn get_commitment(State(session): State<Arc<Sequencer>>) -> impl IntoResponse {
    match session.get_commitment().await {
        Ok(commitment) => (StatusCode::OK, Json(commitment)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
