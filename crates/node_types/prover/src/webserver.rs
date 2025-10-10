use anyhow::{Result, bail};
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
use tokio_util::sync::CancellationToken;
use tower_http::cors::CorsLayer;
use utoipa::{
    OpenApi,
    openapi::{Info, OpenApiBuilder},
};
use utoipa_axum::{router::OpenApiRouter, routes};
use utoipa_swagger_ui::SwaggerUi;

/// Configuration for the embedded web server in Prism nodes.
///
/// Controls whether the HTTP server is enabled and where it binds for client connections.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WebServerConfig {
    /// Whether to enable the web server.
    /// When disabled, no HTTP endpoints will be available.
    pub enabled: bool,

    /// Host address to bind the web server to.
    /// Use "127.0.0.1" for localhost only or "0.0.0.0" for all interfaces.
    pub host: String,

    /// Port number for the web server.
    /// Should be unique per node instance.
    pub port: u16,
}

impl Default for WebServerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            host: "127.0.0.1".to_string(),
            port: 41997,
        }
    }
}

pub struct WebServer<P: PrismApi + 'static> {
    pub cfg: WebServerConfig,
    pub prism: Arc<P>,
    cancellation_token: CancellationToken,
}

#[derive(OpenApi)]
struct ApiDoc;

impl<P: PrismApi + 'static> WebServer<P> {
    pub const fn new(
        cfg: WebServerConfig,
        prism: Arc<P>,
        cancellation_token: CancellationToken,
    ) -> Self {
        Self {
            cfg,
            prism,
            cancellation_token,
        }
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
            .with_state(self.prism.clone())
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

        let cancellation_token = self.cancellation_token.clone();
        server
            .with_graceful_shutdown(async move {
                cancellation_token.cancelled().await;
                info!("Webserver shutting down gracefully");
            })
            .await?;

        Ok(())
    }
}

/// Updates or inserts a transaction in the transparency dictionary, pending inclusion in the next
/// epoch.
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
async fn post_transaction<P: PrismApi>(
    State(prism): State<Arc<P>>,
    Json(transaction): Json<Transaction>,
) -> impl IntoResponse {
    match prism.post_transaction(transaction).await {
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
/// If the ID is not found in the database, the endpoint will return a 400 response with the message
/// "Could not calculate values".
#[utoipa::path(
    post,
    path = "/get-account",
    request_body = AccountRequest,
    responses(
        (status = 200, description = "Successfully retrieved valid keys", body = AccountResponse),
        (status = 400, description = "Bad request")
    )
)]
async fn get_account<P: PrismApi>(
    State(prism): State<Arc<P>>,
    Json(request): Json<AccountRequest>,
) -> impl IntoResponse {
    let get_account_result = prism.get_account(&request.id).await;
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

/// Returns the commitment (tree root) of the `IndexedMerkleTree` initialized from the database.
#[utoipa::path(
    get,
    path = "/get-current-commitment",
    responses(
        (status = 200, description = "Successfully retrieved current commitment", body = CommitmentResponse),
        (status = 500, description = "Internal server error")
    )
)]
async fn get_commitment<P: PrismApi>(State(prism): State<Arc<P>>) -> impl IntoResponse {
    match prism.get_commitment().await {
        Ok(commitment_response) => (StatusCode::OK, Json(commitment_response)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
