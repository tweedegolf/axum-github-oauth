/// This module contains the request handlers for the GitHub OAuth flow.
/// It includes functions for login, logout, and authorization.
/// These handlers are used by the Axum framework to handle incoming HTTP requests.
use axum::{
    extract::Query,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::Cookie;
use cookie::SameSite;
use http::{
    header::{ACCEPT, USER_AGENT},
    HeaderValue,
};
use oauth2::{reqwest::async_http_client, AuthorizationCode, CsrfToken, Scope, TokenResponse};
use serde::Deserialize;
use std::fmt::Debug;

use crate::{
    CookieStorage, Error, GithubOauthService, User, COOKIE_NAME, CSRF_COOKIE_NAME,
    GITHUB_ACCEPT_TYPE, GITHUB_ORGS_URL, GITHUB_USER_URL, USER_AGENT_VALUE,
};

/// Handles the login request.
/// Generates the authorization URL and CSRF token, sets the CSRF token as a cookie,
/// and redirects the user to the authorization URL.
///
/// # Parameters
///
/// - `service`: The `GithubOauthService` instance.
/// - `jar`: The private cookie jar to store the CSRF token cookie.
///
/// # Returns
///
/// Returns a `Result` containing the updated cookie jar and a `Redirect` response.
/// If successful, the user will be redirected to the authorization URL.
///
/// # Errors
///
/// Returns an `Error` if there is an issue generating the CSRF token or setting the cookie.
pub(super) async fn login(
    service: GithubOauthService,
    cookie_storage: CookieStorage,
) -> Result<impl IntoResponse, Error> {
    let jar = cookie_storage.jar;

    // Generate the authorization URL and CSRF token
    let (auth_url, csrf_token) = service
        .oauth_client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("read:user".to_string()))
        .add_scope(Scope::new("read:org".to_string()))
        .url();

    // Serialize the CSRF token as a string
    let csrf_cookie_value = serde_json::to_string(&csrf_token)?;

    // Create a new CSRF token cookie
    let mut csrf_cookie = Cookie::new(CSRF_COOKIE_NAME, csrf_cookie_value);

    // Set cookie attributes
    csrf_cookie.set_http_only(true);
    csrf_cookie.set_secure(true);
    csrf_cookie.set_same_site(SameSite::Lax);
    csrf_cookie.set_max_age(cookie::time::Duration::minutes(60));
    csrf_cookie.set_path("/");

    // Add the CSRF token cookie to the cookie jar
    let updated_jar = jar.add(csrf_cookie);

    // Return the updated cookie jar and a redirect response to the authorization URL
    Ok((updated_jar, Redirect::to(auth_url.to_string().as_str())))
}

/// Handles the logout request.
/// Removes the session cookie from the cookie jar and returns a simple message indicating successful logout.
///
/// # Parameters
///
/// - `jar`: The private cookie jar containing the session cookie.
///
/// # Returns
///
/// Returns a tuple containing the updated cookie jar and a simple logout message.
pub(super) async fn logout(storage: CookieStorage) -> impl IntoResponse {
    let mut jar = storage.jar;

    // Remove the session cookie from the cookie jar
    if let Some(cookie) = jar.get(COOKIE_NAME) {
        jar = jar.remove(cookie);
    }

    // Return the updated cookie jar and a logout message
    (jar, "You are now logged out 👋")
}

/// Represents the request parameters for the authorization request.
#[derive(Debug, Deserialize)]
pub(super) struct AuthRequest {
    code: String,
    state: String,
}

/// Represents a GitHub organization.
#[derive(Debug, Deserialize)]
struct Organisation {
    login: String,
}

/// Handles the authorization request.
/// Exchanges the authorization code for an access token,
/// validates the CSRF token, fetches user data and organizations,
/// and sets the session cookie if the user is authorized.
///
/// # Parameters
///
/// - `service`: The `GithubOauthService` instance.
/// - `Query(query)`: The query parameters containing the authorization code and CSRF token.
/// - `jar`: The private cookie jar containing the CSRF token cookie.
///
/// # Returns
///
/// Returns a `Result` containing the updated cookie jar and a redirect response to the home page.
/// If successful, the user will be redirected to the home page with the session cookie set.
///
/// # Errors
///
/// Returns an `Error` if there is an issue exchanging the authorization code for an access token,
/// validating the CSRF token, fetching user data or organizations, or setting the session cookie.
pub(super) async fn authorize(
    service: GithubOauthService,
    Query(query): Query<AuthRequest>,
    cookie_storage: CookieStorage,
) -> Result<Response, Error> {
    let jar = cookie_storage.jar;

    // Exchange the authorization code for an access token
    let token = service
        .oauth_client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client)
        .await
        .map_err(|e| Error::Oauth(e.to_string()))?;

    // Get the CSRF token cookie from the cookie jar
    let mut csrf_cookie = jar
        .get(CSRF_COOKIE_NAME)
        .ok_or_else(|| Error::MissingCSRFCookie)?;

    // Set cookie attributes
    csrf_cookie.set_same_site(SameSite::Lax);
    csrf_cookie.set_http_only(true);
    csrf_cookie.set_secure(true);
    csrf_cookie.set_path("/");

    // Deserialize the CSRF token from the cookie value
    let csrf_token: CsrfToken = serde_json::from_str(csrf_cookie.value())?;

    // Validate the CSRF token
    if query.state != *csrf_token.secret() {
        return Err(Error::CSRFTokenMismatch);
    }

    // Create a new HTTP client
    let client = reqwest::Client::new();

    // Fetch user data from the GitHub API
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

    // Fetch organizations from the GitHub API
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

    // Check if the user is authorized based on the configured organization
    if let Some(organisation) = service.config.organisation {
        if !orgs.iter().any(|org| org.login == organisation) {
            return Ok(format!(
                "User {} not in the {organisation} organisation.",
                user_data.login
            )
            .into_response());
        }
    }

    // Serialize the user data as a string
    let session_cookie_value = serde_json::to_string(&user_data)?;

    // Create a new session cookie
    let mut session_cookie = Cookie::new(COOKIE_NAME, session_cookie_value);
    session_cookie.set_http_only(true);
    session_cookie.set_secure(true);
    session_cookie.set_same_site(cookie::SameSite::Lax);
    session_cookie.set_max_age(cookie::time::Duration::hours(10));
    session_cookie.set_path("/");

    // Remove the CSRF token cookie and add the session cookie to the cookie jar
    let updated_jar = jar.remove(csrf_cookie).add(session_cookie);

    // Return the updated cookie jar and a redirect response to the home page
    Ok((updated_jar, Redirect::to("/")).into_response())
}
