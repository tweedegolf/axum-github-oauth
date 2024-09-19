use axum::response::{Html, IntoResponse, Response};
use http::StatusCode;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("missing variable from environment: {0}")]
    MissingEnvironmentVariable(&'static str),
    #[error("oauth {0}")]
    Oauth(String),
    #[error("oauth token {0}")]
    OauthToken(String),
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

impl Error {
    pub fn user_message(&self) -> String {
        match self {
            Self::MissingEnvironmentVariable(name) => {
                format!("Missing environment variable: {}", name)
            }
            Self::Oauth(msg) => msg.clone(),
            Self::OauthToken(_) => "Error fetching OAuth token".to_string(),
            Self::FetchUser(_) => "An error occurred while fetching the GitHub user".to_string(),
            Self::ParseUser(_) => "An error occurred while parsing the GitHub user".to_string(),
            Self::FetchOrganisations(_) => {
                "An error occurred while fetching the GitHub organisations".to_string()
            }
            Self::ParseOrganisations(_) => {
                "An error occurred while parsing the GitHub organisations".to_string()
            }
            Self::Json(_) => "An error occurred while processing JSON".to_string(),
            Self::DeserializeUser(_) => {
                "An error occurred while deserializing the user".to_string()
            }
            Self::MissingCSRFCookie => "Missing CSRF cookie".to_string(),
            Self::CSRFTokenMismatch => "The CSRF token did not match".to_string(),
            Self::ServiceNotFound => "Service not found".to_string(),
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        tracing::error!("Application error: {:#}", self.to_string());

        let body = Html(format!(
            r#"<h3>{}</h3><p><a href="/login">Try again<a></p>"#,
            self.user_message()
        ));

        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}
