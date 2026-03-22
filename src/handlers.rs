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
    HeaderMap, HeaderValue,
};
use oauth2::{reqwest as oauth2_reqwest, AuthorizationCode, CsrfToken, Scope, TokenResponse};
use reqwest::redirect::Policy;
use serde::Deserialize;
use std::{fmt::Debug, time::Duration};
use tracing::{debug, info, warn};

use crate::{
    CookieStorage, Error, GithubOauthService, User, COOKIE_NAME, CSRF_COOKIE_NAME,
    GITHUB_ACCEPT_TYPE, GITHUB_EMAILS_URL, GITHUB_USER_URL, USER_AGENT_VALUE,
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
    info!(
        redirect_url = %service.config.redirect_url,
        "starting GitHub OAuth login flow"
    );

    // Generate the authorization URL and CSRF token
    let (auth_url, csrf_token) = service
        .oauth_client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("read:user".to_string()))
        .add_scope(Scope::new("user:email".to_string()))
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

    debug!(authorize_url = %auth_url, "generated GitHub authorization URL");

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
    let had_session_cookie = jar.get(COOKIE_NAME).is_some();

    // Remove the session cookie from the cookie jar
    if let Some(mut cookie) = jar.get(COOKIE_NAME) {
        // Set cookie attributes (necessary for removal) and remove it from the jar
        cookie.set_http_only(true);
        cookie.set_secure(true);
        cookie.set_same_site(cookie::SameSite::Lax);
        cookie.set_path("/");

        jar = jar.remove(cookie);
    }

    info!(had_session_cookie, "processed logout request");

    // Return the updated cookie jar and a logout message
    (jar, "You are now logged out 👋")
}

/// Represents the request parameters for the authorization request.
#[derive(Debug, Deserialize)]
pub(super) struct AuthRequest {
    code: String,
    state: String,
}

#[derive(Debug, Deserialize)]
struct GitHubUser {
    pub id: usize,
    pub login: String,
    pub avatar_url: String,
}

#[derive(Debug, Deserialize)]
struct GitHubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

#[derive(Debug)]
struct RequestIpHeaders<'a> {
    forwarded: Option<&'a str>,
    x_forwarded_for: Option<&'a str>,
    x_real_ip: Option<&'a str>,
    cf_connecting_ip: Option<&'a str>,
    true_client_ip: Option<&'a str>,
}

impl<'a> RequestIpHeaders<'a> {
    fn is_empty(&self) -> bool {
        self.forwarded.is_none()
            && self.x_forwarded_for.is_none()
            && self.x_real_ip.is_none()
            && self.cf_connecting_ip.is_none()
            && self.true_client_ip.is_none()
    }
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn request_ip_headers(headers: &HeaderMap) -> RequestIpHeaders<'_> {
    RequestIpHeaders {
        forwarded: header_value(headers, "forwarded"),
        x_forwarded_for: header_value(headers, "x-forwarded-for"),
        x_real_ip: header_value(headers, "x-real-ip"),
        cf_connecting_ip: header_value(headers, "cf-connecting-ip"),
        true_client_ip: header_value(headers, "true-client-ip"),
    }
}

fn truncate_for_log(value: &str, max_chars: usize) -> String {
    let total_chars = value.chars().count();
    let mut truncated: String = value.chars().take(max_chars).collect();

    if total_chars > max_chars {
        truncated.push_str("...");
    }

    truncated
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
    headers: HeaderMap,
    cookie_storage: CookieStorage,
) -> Result<Response, Error> {
    let jar = cookie_storage.jar;
    let ip_headers = request_ip_headers(&headers);

    info!(
        has_csrf_cookie = jar.get(CSRF_COOKIE_NAME).is_some(),
        ?ip_headers,
        "received GitHub OAuth callback"
    );

    if ip_headers.is_empty() {
        warn!("no inbound IP-related headers were present on the OAuth callback request");
    }

    let http_client = oauth2_reqwest::ClientBuilder::new()
        .redirect(oauth2_reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| Error::OauthToken(e.to_string()))?;

    // Exchange the authorization code for an access token
    debug!("exchanging OAuth authorization code for access token");
    let token = service
        .oauth_client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(&http_client)
        .await
        .map_err(|e| Error::OauthToken(e.to_string()))?;
    debug!("successfully exchanged OAuth authorization code");

    // Get the CSRF token cookie from the cookie jar
    let mut csrf_cookie = match jar.get(CSRF_COOKIE_NAME) {
        Some(cookie) => cookie,
        None => {
            warn!("missing CSRF cookie on OAuth callback");
            return Err(Error::MissingCSRFCookie);
        }
    };

    // Set cookie attributes
    csrf_cookie.set_same_site(SameSite::Lax);
    csrf_cookie.set_http_only(true);
    csrf_cookie.set_secure(true);
    csrf_cookie.set_path("/");

    // Deserialize the CSRF token from the cookie value
    let csrf_token: CsrfToken = serde_json::from_str(csrf_cookie.value())?;

    // Validate the CSRF token
    if query.state != *csrf_token.secret() {
        warn!("CSRF token mismatch on OAuth callback");
        return Err(Error::CSRFTokenMismatch);
    }
    debug!("validated CSRF token");

    // Create a new HTTP client
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|e| Error::FetchUser(e.to_string()))?;

    // Fetch user data from the GitHub API
    debug!("fetching GitHub user profile");
    let user_data: GitHubUser = client
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
    info!(
        user_id = user_data.id,
        login = %user_data.login,
        "fetched GitHub user profile"
    );

    // Check the username against an endpoint
    let url = service
        .config
        .check_url
        .replace("{username}", &user_data.login);
    info!(
        login = %user_data.login,
        check_url = %url,
        ?ip_headers,
        "calling authorization check endpoint"
    );
    let response = match client.get(&url).send().await {
        Ok(response) => response,
        Err(error) => {
            warn!(
                login = %user_data.login,
                check_url = %url,
                ?ip_headers,
                error = %error,
                "authorization check request failed"
            );
            return Err(Error::Authorized(url));
        }
    };

    let check_status = response.status();
    if !check_status.is_success() {
        let response_body = response
            .text()
            .await
            .unwrap_or_else(|error| format!("<failed to read response body: {error}>"));
        let response_body_preview = truncate_for_log(&response_body, 256);
        warn!(
            login = %user_data.login,
            check_url = %url,
            status = %check_status,
            ?ip_headers,
            response_body = %response_body_preview,
            "authorization check endpoint rejected the user"
        );
        return Err(Error::Authorized(url));
    }
    info!(
        login = %user_data.login,
        check_url = %url,
        status = %check_status,
        "authorization check endpoint accepted the user"
    );

    // Fetch email addresses from the GitHub API
    debug!(login = %user_data.login, "fetching GitHub email addresses");
    let emails: Vec<GitHubEmail> = client
        .get(GITHUB_EMAILS_URL)
        .header(ACCEPT, HeaderValue::from_static(GITHUB_ACCEPT_TYPE))
        .header(USER_AGENT, HeaderValue::from_static(USER_AGENT_VALUE))
        .bearer_auth(token.access_token().secret())
        .send()
        .await
        .map_err(|e| Error::FetchUser(e.to_string()))?
        .json()
        .await
        .map_err(|e| Error::ParseUser(e.to_string()))?;
    debug!(
        login = %user_data.login,
        email_count = emails.len(),
        "fetched GitHub email addresses"
    );

    let mut email = None;

    // find the email address that contains the organization name
    'outer: for domain in service.config.email_domains {
        for e in &emails {
            if e.email.ends_with(&domain) {
                email = Some(e.email.clone());
                info!(
                    login = %user_data.login,
                    matched_domain = %domain,
                    "selected GitHub email matching configured domain"
                );
                break 'outer;
            }
        }
    }

    // if no email address contains the organization name, find the primary email address
    if email.is_none() {
        for e in &emails {
            if e.primary && e.verified {
                email = Some(e.email.clone());
                info!(
                    login = %user_data.login,
                    "selected primary verified GitHub email"
                );
                break;
            }
        }
    }

    // if no primary email address is found, return an error
    let email = match email {
        Some(email) => email,
        None => {
            warn!(
                login = %user_data.login,
                "no verified GitHub email address matched the configured domains or primary fallback"
            );
            return Ok("No verified and primary email address found".into_response());
        }
    };

    let user: User = User {
        id: user_data.id,
        login: user_data.login,
        email,
        avatar_url: user_data.avatar_url,
    };

    // Serialize the user data as a string
    let session_cookie_value = serde_json::to_string(&user)?;

    // Create a new session cookie
    let mut session_cookie = Cookie::new(COOKIE_NAME, session_cookie_value);
    session_cookie.set_http_only(true);
    session_cookie.set_secure(true);
    session_cookie.set_same_site(cookie::SameSite::Lax);
    session_cookie.set_max_age(cookie::time::Duration::days(30));
    session_cookie.set_path("/");

    // Remove the CSRF token cookie and add the session cookie to the cookie jar
    let updated_jar = jar.remove(csrf_cookie).add(session_cookie);

    info!(
        user_id = user.id,
        login = %user.login,
        "completed GitHub OAuth authorization flow"
    );

    // Return the updated cookie jar and a redirect response to the home page
    Ok((updated_jar, Redirect::to("/")).into_response())
}
