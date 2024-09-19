use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    RequestPartsExt, Router,
};
use axum_extra::extract::PrivateCookieJar;
use handlers::{authorize, login, logout};
use http::{request::Parts, HeaderMap};
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::{convert::Infallible, env, fmt::Debug};
use url::Url;

static COOKIE_NAME: &str = "SESSION";
static CSRF_COOKIE_NAME: &str = "CSRF";
static USER_AGENT_VALUE: &str = "axum-github-oauth";

static GITHUB_AUTH_URL: &str = "https://github.com/login/oauth/authorize";
static GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
static GITHUB_USER_URL: &str = "https://api.github.com/user";
static GITHUB_EMAILS_URL: &str = "https://api.github.com/user/emails";
static GITHUB_ORGS_URL: &str = "https://api.github.com/user/orgs";
static GITHUB_ACCEPT_TYPE: &str = "application/vnd.github+json";

mod error;
mod handlers;

pub use error::Error;

/// Represents the GitHub OAuth service.
#[derive(Clone)]
pub struct GithubOauthService {
    oauth_client: BasicClient,
    config: Config,
}

#[async_trait]
impl<S> FromRequestParts<S> for GithubOauthService
where
    GithubOauthService: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(GithubOauthService::from_ref(state))
    }
}

pub(crate) struct CookieStorage {
    pub(crate) jar: PrivateCookieJar,
}

#[async_trait]
impl<S> FromRequestParts<S> for CookieStorage
where
    GithubOauthService: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let service = GithubOauthService::from_ref(state);
        let jar =
            PrivateCookieJar::from_headers(&parts.headers, service.config.session_key.clone());

        Ok(Self { jar })
    }
}

/// Represents a user retrieved from GitHub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: usize,
    pub login: String,
    pub email: String,
    pub avatar_url: String,
}

/// Represents the configuration for the GitHub OAuth service.
#[derive(Clone)]
pub struct Config {
    // github endpoints
    pub auth_url: Url,
    pub token_url: Url,
    // application specific settings / secrets
    pub organisation: Option<String>,
    pub session_key: cookie::Key,
    pub redirect_url: Url,
    // paths
    pub login_path: String,
    pub authorize_path: String,
    pub logout_path: String,
}

impl Default for Config {
    fn default() -> Self {
        let redirect_url = env::var("REDIRECT_URL")
            .expect("missing REDIRECT_URL from environment")
            .parse()
            .expect("failed to parse REDIRECT_URL");

        let mut hasher = Sha512::new();
        let session_key_input =
            env::var("SESSION_KEY").expect("missing SESSION_KEY from environment");
        hasher.update(session_key_input.as_bytes());
        let session_key = cookie::Key::from(hasher.finalize().as_slice());

        Self {
            auth_url: Url::parse(GITHUB_AUTH_URL).unwrap(),
            token_url: Url::parse(GITHUB_TOKEN_URL).unwrap(),
            organisation: None,
            session_key,
            redirect_url,
            login_path: "/login".to_string(),
            authorize_path: "/authorize".to_string(),
            logout_path: "/logout".to_string(),
        }
    }
}

impl GithubOauthService {
    /// Creates a new instance of `GithubOauthService`.
    ///
    /// # Arguments
    ///
    /// * `config` - Optional configuration for the service. If not provided, default configuration will be used.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the `GithubOauthService` instance or an `Error` if there was an error creating the service.
    pub fn new(config: Option<Config>) -> Result<Self, Error> {
        let config = config.unwrap_or_default();
        let client_id = env::var("OAUTH_CLIENT_ID")
            .map_err(|_| Error::MissingEnvironmentVariable("OAUTH_CLIENT_ID"))?;
        let client_secret = env::var("OAUTH_CLIENT_SECRET")
            .map_err(|_| Error::MissingEnvironmentVariable("OAUTH_CLIENT_SECRET"))?;

        let oauth_client = BasicClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
            AuthUrl::from_url(config.auth_url.clone()),
            Some(TokenUrl::from_url(config.token_url.clone())),
        )
        .set_redirect_uri(RedirectUrl::from_url(config.redirect_url.clone()));

        Ok(Self {
            oauth_client,
            config,
        })
    }

    /// Checks if a given path is public.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to check.
    ///
    /// # Returns
    ///
    /// Returns `true` if the path is public, `false` otherwise.
    pub fn is_public(&self, path: &str) -> bool {
        path == self.config.login_path
            || path == self.config.authorize_path
            || path == self.config.logout_path
    }

    /// Creates a router for the GitHub OAuth service.
    ///
    /// # Returns
    ///
    /// Returns a `Router` instance for the service.
    pub fn router<S>(&self) -> Router<S>
    where
        GithubOauthService: FromRef<S>,
        S: Clone + Send + Sync + 'static,
    {
        Router::<S>::new()
            .route(&self.config.login_path, get(login))
            .route(&self.config.authorize_path, get(authorize))
            .route(&self.config.logout_path, get(logout))
    }
}

/// Represents an action to perform after authentication.
pub enum AuthAction {
    /// Redirects to the specified path.
    Redirect(String),
    /// Represents an error that occurred during authentication.
    Error(Error),
}

impl IntoResponse for AuthAction {
    fn into_response(self) -> Response {
        match self {
            Self::Redirect(path) => Redirect::temporary(&path).into_response(),
            Self::Error(e) => e.into_response(),
        }
    }
}

impl User {
    /// Creates a `User` instance from the headers and the GitHub OAuth service.
    ///
    /// # Arguments
    ///
    /// * `headers` - The headers containing the session cookie.
    /// * `state` - The GitHub OAuth service instance.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the `User` instance or an `AuthAction` if there was an error creating the user.
    pub fn from_headers_and_service(
        headers: &HeaderMap,
        service: &GithubOauthService,
    ) -> Result<Self, AuthAction> {
        let jar = PrivateCookieJar::from_headers(headers, service.config.session_key.clone());
        let session_cookie = jar
            .get(COOKIE_NAME)
            .ok_or(AuthAction::Redirect(service.config.login_path.clone()))?;

        let user: User = serde_json::from_str(session_cookie.value())
            .map_err(|e| AuthAction::Error(Error::DeserializeUser(e)))?;

        Ok(user)
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for User
where
    GithubOauthService: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthAction;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let service = parts
            .extract_with_state(state)
            .await
            .map_err(|_| AuthAction::Error(Error::ServiceNotFound))?;

        User::from_headers_and_service(&parts.headers, &service)
    }
}
