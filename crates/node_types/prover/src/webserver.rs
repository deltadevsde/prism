use crate::Prover;
use anyhow::{Context, Result, bail};
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use prism_common::{
    api::{
        PrismApi,
        types::{AccountRequest, AccountResponse, CommitmentResponse},
    },
    transaction::Transaction,
};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use utoipa::{
    OpenApi,
    openapi::{Info, OpenApiBuilder},
};
use utoipa_axum::{router::OpenApiRouter, routes};
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

#[derive(OpenApi)]
struct ApiDoc;

impl WebServer {
    pub fn new(cfg: WebServerConfig, session: Arc<Prover>) -> Self {
        Self { cfg, session }
    }

    pub async fn start(&self) -> Result<()> {
        if !self.cfg.enabled {
            bail!("Webserver is disabled")
        }

        let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
            .routes(routes!(get_account))
            .routes(routes!(post_transaction))
            .routes(routes!(get_commitment))
            .layer(CorsLayer::permissive())
            .with_state(self.session.clone())
            .split_for_parts();

        let api = OpenApiBuilder::from(api).info(Info::new("Prism Full Node API", "0.1.0")).build();

        let router = router.merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", api));

        let addr = SocketAddr::new(
            self.cfg.host.parse().expect("IP address can be parsed"),
            self.cfg.port,
        );
        let listener = TcpListener::bind(addr).await.expect("Binding to address works");
        let server = axum::serve(listener, router.into_make_service());

        let socket_addr = server.local_addr()?;
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
    request_body = Transaction,
    responses(
        (status = 200, description = "Entry update queued for insertion into next epoch"),
        (status = 400, description = "Bad request"),
        (status = 500, description = "Internal server error")
    )
)]
async fn post_transaction(
    State(session): State<Arc<Prover>>,
    Json(transaction): Json<Transaction>,
) -> impl IntoResponse {
    match session.validate_and_queue_update(transaction).await {
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
    request_body = AccountRequest,
    responses(
        (status = 200, description = "Successfully retrieved valid keys", body = AccountResponse),
        (status = 400, description = "Bad request")
    )
)]
async fn get_account(
    State(session): State<Arc<Prover>>,
    Json(request): Json<AccountRequest>,
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

    (StatusCode::OK, Json(account_response)).into_response()
}

/// Returns the commitment (tree root) of the IndexedMerkleTree initialized from the database.
///
#[utoipa::path(
    get,
    path = "/get-current-commitment",
    responses(
        (status = 200, description = "Successfully retrieved current commitment", body = CommitmentResponse),
        (status = 500, description = "Internal server error")
    )
)]
async fn get_commitment(State(session): State<Arc<Prover>>) -> impl IntoResponse {
    match session.get_commitment().await {
        Ok(commitment_response) => (StatusCode::OK, Json(commitment_response)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
