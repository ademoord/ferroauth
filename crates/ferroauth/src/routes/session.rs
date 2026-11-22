//! Session endpoints: get-session, sign-out, list/revoke sessions.

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::context::Auth;
use crate::error::{AuthError, Result};
use crate::models::{Session, SessionWithUser};
use crate::session::{self as sess, clear_session_cookies, require_session, resolve_session_token, ApiResponse, RequestMeta};

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetSessionQuery {
    #[serde(default)]
    pub disable_refresh: Option<bool>,
    #[serde(default)]
    pub disable_cookie_cache: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct Success {
    pub success: bool,
}

#[derive(Debug, Serialize)]
pub struct Status {
    pub status: bool,
}

impl Status {
    pub(crate) fn ok() -> ApiResponse<Status> {
        ApiResponse::ok(Status { status: true })
    }
}

#[derive(Debug, Deserialize)]
pub struct RevokeSession {
    pub token: String,
}

/// `GET /get-session` → `{ session, user }` or `null`.
pub async fn get_session(auth: &Auth, meta: &RequestMeta, q: GetSessionQuery) -> Result<ApiResponse<Option<SessionWithUser>>> {
    let lookup = sess::get_session(auth, &meta.headers, q.disable_refresh != Some(true)).await?;
    Ok(ApiResponse::ok(lookup.data).with_cookies(lookup.cookies))
}

/// `POST /sign-out` → `{ success: true }`.
pub async fn sign_out(auth: &Auth, meta: &RequestMeta) -> Result<ApiResponse<Success>> {
    if let Some((token, _)) = resolve_session_token(auth, &meta.headers).await {
        auth.db.delete_session(&token).await?;
    }
    Ok(ApiResponse::ok(Success { success: true }).with_cookies(clear_session_cookies(auth)))
}

/// `GET /list-sessions` → active sessions of the current user.
pub async fn list_sessions(auth: &Auth, meta: &RequestMeta) -> Result<ApiResponse<Vec<Session>>> {
    let current = require_session(auth, &meta.headers).await?;
    let now = Utc::now();
    let sessions = auth.db.list_sessions(&current.user.id).await?.into_iter().filter(|s| s.expires_at > now).collect();
    Ok(ApiResponse::ok(sessions))
}

/// `POST /revoke-session` `{ token }`.
pub async fn revoke_session(auth: &Auth, meta: &RequestMeta, body: RevokeSession) -> Result<ApiResponse<Status>> {
    let current = require_session(auth, &meta.headers).await?;
    match auth.db.find_session(&body.token).await? {
        Some((s, _)) if s.user_id == current.user.id => auth.db.delete_session(&body.token).await?,
        _ => return Err(AuthError::bad_request("SESSION_NOT_FOUND", "Session not found")),
    }
    Ok(Status::ok())
}

/// `POST /revoke-sessions` — every session of the user, including this one.
pub async fn revoke_sessions(auth: &Auth, meta: &RequestMeta) -> Result<ApiResponse<Status>> {
    let current = require_session(auth, &meta.headers).await?;
    auth.db.delete_user_sessions(&current.user.id).await?;
    Ok(Status::ok().with_cookies(clear_session_cookies(auth)))
}

/// `POST /revoke-other-sessions`.
pub async fn revoke_other_sessions(auth: &Auth, meta: &RequestMeta) -> Result<ApiResponse<Status>> {
    let current = require_session(auth, &meta.headers).await?;
    auth.db.delete_other_sessions(&current.user.id, &current.session.token).await?;
    Ok(Status::ok())
}
