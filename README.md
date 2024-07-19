# Axum github oauth

Basic github oauth service for axum with an optional check whether a users belongs to a specified organisation.

## Configuration

Environment variables:

```
OAUTH_CLIENT_ID="<...snip...>"
OAUTH_CLIENT_SECRET="<...snip...>"
REDIRECT_URL="https://example.com/authorize"
ORGANISATION="your-organisation-name"
SESSION_KEY="some-long-random-string"
```

## Example

```rust
use axum::{
    extract::{Request, State},
    middleware, RequestExt, Router,
};
use axum_github_oauth::{AuthAction, GithubOauthService, User};

/// Middleware to check if the user is authorized.
async fn auth(
    State(state): State<GithubOauthService>,
    mut request: Request,
) -> Result<Request, AuthAction> {
    match request.uri().path() {
        path if state.is_public(path) => Ok(request),
        _ => request
            .extract_parts_with_state::<User, GithubOauthService>(&state)
            .await
            .map(|_user| request),
    }
}

#[tokio::main]
async fn main() {
    let oauth_service = GithubOauthService::new(None).unwrap();

    let app = Router::new()
        .merge(oauth_service.router())
        .layer(middleware::map_request_with_state(
            oauth_service.clone(),
            auth,
        ))
        .with_state(oauth_service);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("failed to bind TcpListener");

    axum::serve(listener, app).await.unwrap();
}


