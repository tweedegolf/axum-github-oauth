use axum::{
    extract::{FromRef, FromRequestParts, Query, Request, State},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use axum_extra::extract::{cookie::Cookie, PrivateCookieJar};
use http::{
    header::{ACCEPT, USER_AGENT},
    HeaderValue, StatusCode,
};
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::env;
use url::Url;

static COOKIE_NAME: &str = "SESSION";
static USER_AGENT_VALUE: &str = "axum-github-oauth";

static GITHUB_AUTH_URL: &str = "https://github.com/login/oauth/authorize";
static GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
static GITHUB_USER_URL: &str = "https://api.github.com/user";
static GITHUB_ORGS_URL: &str = "https://api.github.com/user/orgs";
static GITHUB_ACCEPT_TYPE: &str = "application/vnd.github+json";

mod error;

pub use error::Error;

#[derive(Clone)]
pub struct GithubOauthService {
    oauth_client: BasicClient,
    config: Config,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    id: usize,
    login: String,
    name: String,
    avatar_url: String,
}

#[derive(Clone)]
pub struct Config {
    // Github endpoints
    pub auth_url: Url,
    pub token_url: Url,
    // Application specific settings / secrets
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

impl FromRef<GithubOauthService> for cookie::Key {
    fn from_ref(service: &GithubOauthService) -> Self {
        service.config.session_key.clone()
    }
}

impl GithubOauthService {
    pub fn new(config: Option<Config>) -> Result<Self, Error> {
        let config = config.unwrap_or_default();
        let client_id = env::var("OAUTH_CLIENT_ID")?;
        let client_secret = env::var("OAUTH_CLIENT_SECRET")?;

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

    pub fn router(&self) -> Router<GithubOauthService> {
        let router = Router::new()
            .route(&self.config.login_path, get(login))
            .route(&self.config.authorize_path, get(authorize))
            .route(&self.config.logout_path, get(logout));

        router
    }
}

async fn login(State(service): State<GithubOauthService>) -> impl IntoResponse {
    let (auth_url, _csrf_token) = service
        .oauth_client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("read:user".to_string()))
        .add_scope(Scope::new("read:org".to_string()))
        .url();

    Redirect::to(auth_url.as_ref())
}

pub async fn logout(mut jar: PrivateCookieJar) -> impl IntoResponse {
    if let Some(cookie) = jar.get(COOKIE_NAME) {
        jar = jar.remove(cookie);
    }

    (jar, "You are now logged out 👋")
}

impl FromRequestParts<GithubOauthService> for User {
    type Rejection = (StatusCode, String);

    fn from_request_parts(req: &Request, user: User) -> Self {
        user
    }
}

/// Middleware function for authentication.
///
/// This function is used as a middleware in the Axum framework to handle authentication.
/// It checks if the user is logged in by checking the session cookie. If the session cookie
/// is present, it extracts the user information from the cookie and adds it to the request's
/// extensions. If the session cookie is not present, it redirects the user to the login page.
///
/// # Arguments
///
/// * `state`: The application state containing the OAuth client and configuration.
/// * `req`: The incoming request.
/// * `next`: The next middleware or handler in the chain.
///
/// # Returns
///
/// Returns a `Result` containing either a `Response` or a `StatusCode`. If the user is logged in,
/// it calls the next middleware or handler. If the user is not logged in, it redirects the user
/// to the login page.
async fn auth(
    State(service): State<GithubOauthService>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Check the path of the request
    match req.uri().path() {
        // If the path is "/login" or "/authorized", call the next middleware or handler
        "/login" | "/authorized" => Ok(next.run(req).await),
        _ => {
            // Extract the session cookie from the request headers
            let jar =
                PrivateCookieJar::from_headers(req.headers(), service.config.session_key.clone());

            // Check if the session cookie is present
            if let Some(session_cookie) = jar.get(COOKIE_NAME) {
                // Deserialize the user information from the session cookie
                if let Ok(user) = serde_json::from_str::<User>(session_cookie.value()) {
                    // Add the user information to the request's extensions
                    req.extensions_mut().insert(user);
                    // Call the next middleware or handler
                    Ok(next.run(req).await)
                } else {
                    // If the session cookie is present but the user information cannot be
                    // deserialized, redirect the user to the login page
                    Ok(Redirect::to("/login").into_response())
                }
            } else {
                // If the session cookie is not present, redirect the user to the login page
                Ok(Redirect::to("/login").into_response())
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct AuthRequest {
    code: String,
    state: String,
}

#[derive(Debug, Deserialize)]
struct Organisation {
    login: String,
}

async fn authorize(
    State(service): State<GithubOauthService>,
    Query(query): Query<AuthRequest>,
    jar: PrivateCookieJar,
) -> Result<Response, Error> {
    let token = service
        .oauth_client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client)
        .await
        .map_err(|e| Error::Oauth(e.to_string()))?;

    let client = reqwest::Client::new();
    let user_data: User = client
        .get(GITHUB_USER_URL)
        .header(ACCEPT, HeaderValue::from_static(GITHUB_ACCEPT_TYPE))
        .header(USER_AGENT, HeaderValue::from_static(USER_AGENT_VALUE))
        .bearer_auth(token.access_token().secret())
        .send()
        .await
        .map_err(|e| Error::FetchUser(e.to_string()))?
        .json()
        .await
        .map_err(|e| Error::ParseUser(e.to_string()))?;

    let orgs: Vec<Organisation> = client
        .get(GITHUB_ORGS_URL)
        .header(ACCEPT, HeaderValue::from_static(GITHUB_ACCEPT_TYPE))
        .header(USER_AGENT, HeaderValue::from_static(USER_AGENT_VALUE))
        .bearer_auth(token.access_token().secret())
        .send()
        .await
        .map_err(|e| Error::FetchOrganisations(e.to_string()))?
        .json()
        .await
        .map_err(|e| Error::ParseOrganisations(e.to_string()))?;

    if let Some(organisation) = service.config.organisation {
        if !orgs.iter().any(|org| org.login == organisation) {
            return Ok(format!(
                "User {} not in the {organisation} organisation.",
                user_data.login
            )
            .into_response());
        }
    }

    let session_cookie_value = serde_json::to_string(&user_data)?;

    let mut session_cookie = Cookie::new(COOKIE_NAME, session_cookie_value);
    session_cookie.set_http_only(true);
    session_cookie.set_secure(true);
    session_cookie.set_same_site(cookie::SameSite::Lax);
    session_cookie.set_max_age(cookie::time::Duration::hours(10));
    session_cookie.set_path("/");

    let updated_jar = jar.add(session_cookie);

    Ok((updated_jar, Redirect::to("/")).into_response())
}
