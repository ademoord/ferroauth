//! Password reset: `POST /request-password-reset` (alias `/forget-password`),
//! `GET /reset-password/{token}`, `POST /reset-password`.

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use super::session::Status;
use super::with_query;
use crate::context::Auth;
use crate::cookies::encode_uri_component;
use crate::crypto::random_string;
use crate::error::{AuthError, Result};
use crate::options::ResetPasswordEmail;
use crate::session::{ApiResponse, RequestMeta};

const PREFIX: &str = "reset-password:";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestPasswordReset {
    pub email: String,
    #[serde(default)]
    pub redirect_to: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub status: bool,
    pub message: String,
}

pub async fn request_password_reset(auth: &Auth, _meta: &RequestMeta, body: RequestPasswordReset) -> Result<ApiResponse<MessageResponse>> {
    let Some(send) = &auth.options.email_and_password.send_reset_password else {
        return Err(AuthError::reset_password_disabled());
    };
    auth.validate_redirect(body.redirect_to.as_deref())?;
    let response = MessageResponse {
        status: true,
        message: "If this email exists in our system, check your email for the reset link".into(),
    };
    let Some(user) = auth.db.find_user_by_email(body.email.trim()).await? else {
        // Hide whether the account exists.
        return Ok(ApiResponse::ok(response));
    };
    let token = random_string(24);
    let expires = Utc::now() + Duration::seconds(auth.options.email_and_password.reset_password_token_expires_in);
    auth.db.create_verification(&format!("{PREFIX}{token}"), &user.id, expires).await?;
    let url = format!(
        "{}/reset-password/{token}?callbackURL={}",
        auth.api_url(),
        encode_uri_component(body.redirect_to.as_deref().unwrap_or("/"))
    );
    send.call(ResetPasswordEmail { user, url, token }).await;
    Ok(ApiResponse::ok(response))
}

#[derive(Debug, Deserialize)]
pub struct ResetCallbackQuery {
    #[serde(rename = "callbackURL")]
    pub callback_url: String,
}

/// The link in the email: validates the token, then redirects to the app's
/// reset page with `?token=...` (or `?error=INVALID_TOKEN`).
pub async fn reset_password_callback(
    State(auth): State<Auth>,
    Path(token): Path<String>,
    Query(q): Query<ResetCallbackQuery>,
) -> Response {
    if let Err(e) = auth.validate_redirect(Some(&q.callback_url)) {
        return e.into_response();
    }
    let valid = match auth.db.find_verification(&format!("{PREFIX}{token}")).await {
        Ok(Some(v)) => v.expires_at > Utc::now(),
        Ok(None) => false,
        Err(e) => return e.into_response(),
    };
    let target = if valid { with_query(&q.callback_url, "token", &token) } else { with_query(&q.callback_url, "error", "INVALID_TOKEN") };
    ApiResponse::redirect_to(target).into_response()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetPassword {
    pub new_password: String,
    pub token: String,
}

pub async fn reset_password(auth: &Auth, _meta: &RequestMeta, body: ResetPassword) -> Result<ApiResponse<Status>> {
    auth.check_password_length(&body.new_password)?;
    let identifier = format!("{PREFIX}{}", body.token);
    let verification = auth.db.find_verification(&identifier).await?.ok_or_else(AuthError::invalid_token)?;
    auth.db.delete_verification(&verification.id).await?;
    if verification.expires_at <= Utc::now() {
        return Err(AuthError::invalid_token());
    }
    let user_id = verification.value;
    let hash = auth.hash_password(&body.new_password).await;
    if auth.db.find_credential_account(&user_id).await?.is_some() {
        auth.db.update_password(&user_id, &hash).await?;
    } else {
        auth.db.create_credential_account(&user_id, &hash).await?;
    }
    if auth.options.email_and_password.revoke_sessions_on_password_reset {
        auth.db.delete_user_sessions(&user_id).await?;
    }
    Ok(Status::ok())
}
