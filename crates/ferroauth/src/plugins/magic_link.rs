//! Magic link plugin: passwordless sign-in by email.
//! `POST /sign-in/magic-link`, `GET /magic-link/verify`.

use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Extension, Router};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};

use super::Plugin;
use crate::context::Auth;
use crate::cookies::encode_uri_component;
use crate::crypto::random_string;
use crate::db::Record;
use crate::error::{AuthError, Result};
use crate::options::{Callback, RateLimitRule};
use crate::routes::is_valid_email;
use crate::routes::session::Status;
use crate::routes::with_query;
use crate::session::{create_session, ApiResponse, JsonBody, RequestMeta};

#[derive(Debug, Clone)]
pub struct MagicLinkEmail {
    pub email: String,
    pub url: String,
    pub token: String,
}

#[derive(Debug, Clone)]
pub struct MagicLinkOptions {
    pub send_magic_link: Callback<MagicLinkEmail>,
    /// Seconds. Default 5 minutes.
    pub expires_in: i64,
    pub disable_sign_up: bool,
}

#[derive(Debug, Clone)]
pub struct MagicLink {
    opts: Arc<MagicLinkOptions>,
}

impl MagicLink {
    pub fn new(send_magic_link: Callback<MagicLinkEmail>) -> Self {
        Self::with_options(MagicLinkOptions { send_magic_link, expires_in: 300, disable_sign_up: false })
    }

    pub fn with_options(opts: MagicLinkOptions) -> Self {
        Self { opts: Arc::new(opts) }
    }
}

#[derive(Debug, Deserialize)]
pub struct SignInMagicLink {
    pub email: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, rename = "callbackURL")]
    pub callback_url: Option<String>,
    #[serde(default, rename = "newUserCallbackURL")]
    pub new_user_callback_url: Option<String>,
    #[serde(default, rename = "errorCallbackURL")]
    pub error_callback_url: Option<String>,
}

pub async fn sign_in_magic_link(auth: &Auth, opts: &MagicLinkOptions, body: SignInMagicLink) -> Result<ApiResponse<Status>> {
    for u in [&body.callback_url, &body.new_user_callback_url, &body.error_callback_url] {
        auth.validate_redirect(u.as_deref())?;
    }
    let email = body.email.trim().to_lowercase();
    if !is_valid_email(&email) {
        return Err(AuthError::invalid_email());
    }
    let token = random_string(32);
    let value = json!({ "email": email, "name": body.name }).to_string();
    auth.db.create_verification(&token, &value, Utc::now() + Duration::seconds(opts.expires_in)).await?;
    let mut url = format!("{}/magic-link/verify?token={token}&callbackURL={}", auth.api_url(), encode_uri_component(body.callback_url.as_deref().unwrap_or("/")));
    if let Some(u) = &body.new_user_callback_url {
        url.push_str(&format!("&newUserCallbackURL={}", encode_uri_component(u)));
    }
    if let Some(u) = &body.error_callback_url {
        url.push_str(&format!("&errorCallbackURL={}", encode_uri_component(u)));
    }
    opts.send_magic_link.call(MagicLinkEmail { email, url, token }).await;
    Ok(Status::ok())
}

#[derive(Debug, Deserialize)]
pub struct VerifyQuery {
    pub token: String,
    #[serde(default, rename = "callbackURL")]
    pub callback_url: Option<String>,
    #[serde(default, rename = "newUserCallbackURL")]
    pub new_user_callback_url: Option<String>,
    #[serde(default, rename = "errorCallbackURL")]
    pub error_callback_url: Option<String>,
}

pub async fn verify_magic_link(auth: &Auth, meta: &RequestMeta, opts: &MagicLinkOptions, q: VerifyQuery) -> Result<ApiResponse<Value>> {
    for u in [&q.callback_url, &q.new_user_callback_url, &q.error_callback_url] {
        auth.validate_redirect(u.as_deref())?;
    }
    let callback = q.callback_url.clone().unwrap_or_else(|| "/".into());
    let error_url = q.error_callback_url.clone().unwrap_or_else(|| callback.clone());
    let fail = |code: &str| Ok(ApiResponse::redirect_to(with_query(&error_url, "error", code)));

    let Some(v) = auth.db.find_verification(&q.token).await? else { return fail("INVALID_TOKEN") };
    auth.db.delete_verification(&v.id).await?;
    if v.expires_at <= Utc::now() {
        return fail("EXPIRED_TOKEN");
    }
    let data: Value = serde_json::from_str(&v.value).unwrap_or(Value::Null);
    let Some(email) = data.get("email").and_then(Value::as_str) else { return fail("INVALID_TOKEN") };

    let (user, is_new) = match auth.db.find_user_by_email(email).await? {
        Some(user) if user.email_verified => (user, false),
        Some(user) => {
            let mut d = Record::new();
            d.insert("emailVerified".into(), true.into());
            (auth.db.update_user(&user.id, d).await?, false)
        }
        None if opts.disable_sign_up => return fail("new_user_signup_disabled"),
        None => {
            let mut d = Record::new();
            d.insert("email".into(), email.into());
            d.insert("name".into(), data.get("name").and_then(Value::as_str).unwrap_or_default().into());
            d.insert("emailVerified".into(), true.into());
            (auth.db.create_user(d).await?, true)
        }
    };
    let (_, cookies) = create_session(auth, &user, meta, false).await?;
    let target = match (is_new, q.new_user_callback_url) {
        (true, Some(u)) => u,
        _ => callback,
    };
    Ok(ApiResponse::redirect_to(target).with_cookies(cookies))
}

#[async_trait]
impl Plugin for MagicLink {
    fn id(&self) -> &'static str {
        "magic-link"
    }

    fn rate_limit_rules(&self) -> Vec<RateLimitRule> {
        vec![RateLimitRule::new("/sign-in/magic-link", 60, 5), RateLimitRule::new("/magic-link/verify", 60, 5)]
    }

    fn routes(&self) -> Option<Router<Auth>> {
        Some(
            Router::new()
                .route(
                    "/sign-in/magic-link",
                    post(
                        |State(a): State<Auth>, Extension(o): Extension<Arc<MagicLinkOptions>>, JsonBody(b): JsonBody<SignInMagicLink>| async move {
                            sign_in_magic_link(&a, &o, b).await
                        },
                    ),
                )
                .route(
                    "/magic-link/verify",
                    get(
                        |State(a): State<Auth>,
                         m: RequestMeta,
                         Extension(o): Extension<Arc<MagicLinkOptions>>,
                         Query(q): Query<VerifyQuery>| async move { verify_magic_link(&a, &m, &o, q).await },
                    ),
                )
                .layer(Extension(self.opts.clone())),
        )
    }
}
