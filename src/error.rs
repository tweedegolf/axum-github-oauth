use axum::response::{IntoResponse, Response};
use http::StatusCode;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("missing variable from environment: {0}")]
    MissingEnvironmentVariable(&'static str),
    #[error("oauth {0}")]
    Oauth(String),
    #[error("fetching github user {0}")]
    FetchUser(String),
    #[error("parsing github user {0}")]
    ParseUser(String),
    #[error("fetching github organisations {0}")]
    FetchOrganisations(String),
    #[error("parsing github organisations {0}")]
    ParseOrganisations(String),
    #[error("json {0}")]
    Json(#[from] serde_json::Error),
    #[error("failed deserializing user {0}")]
    DeserializeUser(serde_json::Error),
    #[error("missing csrf cookie")]
    MissingCSRFCookie,
    #[error("the CSRF token did not match")]
    CSRFTokenMismatch,
    #[error("invalid state")]
    ServiceNotFound,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        tracing::error!("Application error: {:#}", self.to_string());

        (StatusCode::INTERNAL_SERVER_ERROR, "Error").into_response()
    }
}
