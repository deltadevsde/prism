use crate::{
    cfg::WebServerConfig,
    error::{DeimosError, DeimosResult, GeneralError},
    node_types::sequencer::Sequencer,
    storage::ChainEntry,
    utils::{decode_signed_message, Signable},
};
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use ed25519::Signature;
use indexed_merkle_tree::tree::{Proof, UpdateProof};
use indexed_merkle_tree::Hash as TreeHash;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
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
pub struct UpdateEntryJson {
    pub signed_incoming_entry: String,
    pub public_key: String,
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
    pub hashchain: Vec<ChainEntry>,
    // pub proof: MerkleProof
}

#[derive(OpenApi)]
#[openapi(
    paths(update_entry, get_hashchain, get_commitment),
    components(schemas(
        UpdateEntryJson,
        EpochData,
        UpdateProofResponse,
        Hash,
        UserKeyRequest,
        UserKeyResponse
    ))
)]
struct ApiDoc;

impl Signable for UpdateEntryJson {
    fn get_signature(&self) -> DeimosResult<Signature> {
        let signed_message_bytes = decode_signed_message(&self.signed_incoming_entry)?;

        // extract the first 64 bytes from the signed message which are the signature
        let signature_bytes: &[u8; 64] = match signed_message_bytes.get(..64) {
            Some(array_section) => match array_section.try_into() {
                Ok(array) => array,
                Err(e) => Err(DeimosError::General(GeneralError::DecodingError(format!(
                    "signed message to array: {}",
                    e
                ))))?,
            },
            None => Err(DeimosError::General(GeneralError::DecodingError(format!(
                "extracting signature from signed message: {}",
                &self.signed_incoming_entry
            ))))?,
        };

        Ok(Signature::from_bytes(signature_bytes))
    }

    fn get_content_to_sign(&self) -> DeimosResult<String> {
        let signed_message_bytes = decode_signed_message(&self.signed_incoming_entry)?;
        let message_bytes = &signed_message_bytes[64..];
        Ok(String::from_utf8_lossy(message_bytes).to_string())
    }

    fn get_public_key(&self) -> DeimosResult<String> {
        Ok(self.public_key.clone())
    }
}

impl WebServer {
    pub fn new(cfg: WebServerConfig) -> Self {
        Self { cfg }
    }

    pub async fn start(&self, session: Arc<Sequencer>) {
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
            .unwrap();
    }
}

/// Updates or inserts an entry in the transparency dictionary, pending inclusion in the next epoch.
///
#[utoipa::path(
    post,
    path = "/update-entry",
    request_body = UpdateEntryJson,
    responses(
        (status = 200, description = "Entry update pending, poll in next epoch for proof"),
        (status = 400, description = "Bad request"),
        (status = 500, description = "Internal server error")
    )
)]
async fn update_entry(
    State(session): State<Arc<Sequencer>>,
    Json(signature_with_key): Json<UpdateEntryJson>,
) -> impl IntoResponse {
    match session.update_entry(&signature_with_key) {
        Ok(_) => (StatusCode::OK, "Entry update pending insertion into epoch").into_response(),
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
    match session.db.get_hashchain(&request.id) {
        Ok(hashchain) => (StatusCode::OK, Json(UserKeyResponse { hashchain })).into_response(),
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
    match session.create_tree() {
        Ok(tree) => match tree.get_commitment() {
            Ok(commitment) => (StatusCode::OK, Json(commitment)).into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        },
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
