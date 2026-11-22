//! HTTP endpoints.
//!
//! Every endpoint is also a plain `pub async fn` taking `&Auth`, so it can be
//! called server-side.

pub mod account;
pub mod email_password;
pub mod password;
pub mod session;
#[cfg(feature = "oauth")]
pub mod social;
pub mod user;
pub mod verification;

use axum::extract::{Query, Request, State};
use axum::http::header::{COOKIE, ORIGIN, REFERER};
use axum::http::Method;
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::context::Auth;
use crate::error::AuthError;
use crate::session::{client_ip, JsonBody, RequestMeta};

pub(crate) fn build_router(auth: Auth) -> Router {
    let mut r: Router<Auth> = Router::new()
        .route("/ok", get(|| async { Json(json!({ "ok": true })) }))
        .route("/error", get(error_page))
        // email & password
        .route("/sign-up/email", post(|State(a): State<Auth>, m: RequestMeta, JsonBody(b)| async move {
            email_password::sign_up_email(&a, &m, b).await
        }))
        .route("/sign-in/email", post(|State(a): State<Auth>, m: RequestMeta, JsonBody(b)| async move {
            email_password::sign_in_email(&a, &m, b).await
        }))
        // session
        .route("/get-session", get(|State(a): State<Auth>, m: RequestMeta, Query(q)| async move {
            session::get_session(&a, &m, q).await
        }))
        .route("/sign-out", post(|State(a): State<Auth>, m: RequestMeta| async move { session::sign_out(&a, &m).await }))
        .route("/list-sessions", get(|State(a): State<Auth>, m: RequestMeta| async move { session::list_sessions(&a, &m).await }))
        .route("/revoke-session", post(|State(a): State<Auth>, m: RequestMeta, JsonBody(b)| async move {
            session::revoke_session(&a, &m, b).await
        }))
        .route("/revoke-sessions", post(|State(a): State<Auth>, m: RequestMeta| async move { session::revoke_sessions(&a, &m).await }))
        .route("/revoke-other-sessions", post(|State(a): State<Auth>, m: RequestMeta| async move {
            session::revoke_other_sessions(&a, &m).await
        }))
        // user
        .route("/update-user", post(|State(a): State<Auth>, m: RequestMeta, JsonBody(b)| async move { user::update_user(&a, &m, b).await }))
        .route("/change-password", post(|State(a): State<Auth>, m: RequestMeta, JsonBody(b)| async move {
            user::change_password(&a, &m, b).await
        }))
        .route("/change-email", post(|State(a): State<Auth>, m: RequestMeta, JsonBody(b)| async move { user::change_email(&a, &m, b).await }))
        .route("/delete-user", post(|State(a): State<Auth>, m: RequestMeta, JsonBody(b)| async move { user::delete_user(&a, &m, b).await }))
        // password reset
        .route("/request-password-reset", post(|State(a): State<Auth>, m: RequestMeta, JsonBody(b)| async move {
            password::request_password_reset(&a, &m, b).await
        }))
        .route("/forget-password", post(|State(a): State<Auth>, m: RequestMeta, JsonBody(b)| async move {
            password::request_password_reset(&a, &m, b).await
        }))
        .route("/reset-password/{token}", get(password::reset_password_callback))
        .route("/reset-password", post(|State(a): State<Auth>, m: RequestMeta, JsonBody(b)| async move {
            password::reset_password(&a, &m, b).await
        }))
        // email verification
        .route("/send-verification-email", post(|State(a): State<Auth>, m: RequestMeta, JsonBody(b)| async move {
            verification::send_verification_email(&a, &m, b).await
        }))
        .route("/verify-email", get(|State(a): State<Auth>, m: RequestMeta, Query(q)| async move {
            verification::verify_email(&a, &m, q).await
        }))
        // accounts
        .route("/list-accounts", get(|State(a): State<Auth>, m: RequestMeta| async move { account::list_accounts(&a, &m).await }))
        .route("/unlink-account", post(|State(a): State<Auth>, m: RequestMeta, JsonBody(b)| async move {
            account::unlink_account(&a, &m, b).await
        }));

    #[cfg(feature = "oauth")]
    {
        r = r
            .route("/sign-in/social", post(|State(a): State<Auth>, m: RequestMeta, JsonBody(b)| async move {
                social::sign_in_social(&a, &m, b).await
            }))
            .route("/link-social", post(|State(a): State<Auth>, m: RequestMeta, JsonBody(b)| async move {
                social::link_social(&a, &m, b).await
            }))
            .route("/callback/{provider}", get(social::callback_get).post(social::callback_post));
    }

    for plugin in &auth.plugins {
        if let Some(pr) = plugin.routes() {
            r = r.merge(pr);
        }
    }

    let r = r
        .layer(from_fn_with_state(auth.clone(), plugin_hooks))
        .layer(from_fn_with_state(auth.clone(), origin_check))
        .layer(from_fn_with_state(auth.clone(), rate_limit))
        .with_state(auth.clone());

    if auth.options.base_path.is_empty() {
        r
    } else {
        Router::new().nest(&auth.options.base_path, r)
    }
}

/// CSRF protection: state-changing requests must come from a trusted origin.
/// Requests carrying cookies must send `Origin` (or `Referer`).
async fn origin_check(State(auth): State<Auth>, req: Request, next: Next) -> Response {
    // OAuth form_post callbacks come from the provider's origin; they are
    // protected by the signed state cookie instead.
    if auth.options.advanced.disable_csrf_check
        || matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS)
        || req.uri().path().starts_with("/callback/")
    {
        return next.run(req).await;
    }
    let headers = req.headers();
    let origin = headers.get(ORIGIN).or_else(|| headers.get(REFERER)).and_then(|v| v.to_str().ok()).filter(|o| *o != "null");
    match origin {
        Some(o) if !auth.is_trusted_origin(o) => {
            tracing::warn!(origin = o, "rejected request from untrusted origin");
            return AuthError::invalid_origin().into_response();
        }
        None if headers.contains_key(COOKIE) => return AuthError::missing_or_null_origin().into_response(),
        _ => {}
    }
    next.run(req).await
}

async fn rate_limit(State(auth): State<Auth>, req: Request, next: Next) -> Response {
    if auth.options.rate_limit.enabled {
        if let Some(ip) = client_ip(&auth, req.headers(), req.extensions().get()) {
            if !auth.rate_limiter.check(&ip, req.uri().path()) {
                return AuthError::too_many_requests().into_response();
            }
        }
    }
    next.run(req).await
}

async fn plugin_hooks(State(auth): State<Auth>, mut req: Request, next: Next) -> Response {
    if auth.plugins.is_empty() {
        return next.run(req).await;
    }
    let info = crate::plugins::RequestInfo { path: req.uri().path().to_string(), headers: req.headers().clone() };
    for p in &auth.plugins {
        match p.on_request(&auth, req).await {
            Ok(r) => req = r,
            Err(res) => return res,
        }
    }
    let mut res = next.run(req).await;
    for p in &auth.plugins {
        res = p.on_response(&auth, &info, res).await;
    }
    res
}

#[derive(Deserialize)]
struct ErrorQuery {
    error: Option<String>,
}

async fn error_page(State(auth): State<Auth>, Query(q): Query<ErrorQuery>) -> Html<String> {
    let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
    let code = esc(q.error.as_deref().unwrap_or("UNKNOWN"));
    Html(format!(
        "<!doctype html><html><head><meta charset=utf-8><meta name=viewport content=\"width=device-width\"><title>{app} – Error</title>\
         <style>body{{font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;padding:16px}}\
         main{{max-width:28rem}}code{{background:#eee;padding:2px 6px;border-radius:4px}}</style></head>\
         <body><main><h1>Something went wrong</h1><p>Error code: <code>{code}</code></p><p><a href=\"/\">Go back home</a></p></main></body></html>",
        app = esc(&auth.options.app_name)
    ))
}

// ---- helpers shared by endpoints -------------------------------------------------------

/// Append a query parameter to a (possibly relative) URL.
pub(crate) fn with_query(url: &str, key: &str, value: &str) -> String {
    let (base, fragment) = match url.split_once('#') {
        Some((b, f)) => (b, Some(f)),
        None => (url, None),
    };
    let sep = if base.contains('?') { '&' } else { '?' };
    let mut out = format!("{base}{sep}{key}={}", crate::cookies::encode_uri_component(value));
    if let Some(f) = fragment {
        out.push('#');
        out.push_str(f);
    }
    out
}

pub(crate) fn is_valid_email(email: &str) -> bool {
    let Some((local, domain)) = email.rsplit_once('@') else { return false };
    !local.is_empty()
        && local.len() <= 64
        && domain.len() <= 255
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !email.chars().any(|c| c.is_whitespace() || c.is_control())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_helper() {
        assert_eq!(with_query("/cb", "token", "a b"), "/cb?token=a%20b");
        assert_eq!(with_query("/cb?x=1#frag", "error", "E"), "/cb?x=1&error=E#frag");
    }

    #[test]
    fn emails() {
        assert!(is_valid_email("a@b.co"));
        assert!(!is_valid_email("a@b"));
        assert!(!is_valid_email("@b.co"));
        assert!(!is_valid_email("a b@c.co"));
    }
}
