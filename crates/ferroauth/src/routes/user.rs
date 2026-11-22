//! User endpoints: update-user, change-password, change-email, delete-user.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::email_password::user_input_fields;
use super::is_valid_email;
use super::session::Status;
use crate::context::Auth;
use crate::crypto::sign_jwt;
use crate::db::Record;
use crate::error::{AuthError, Result};
use crate::models::User;
use crate::options::ChangeEmailVerification;
use crate::session::{clear_session_cookies, create_session, is_fresh, require_session, ApiResponse, RequestMeta};

/// `POST /update-user` — `name`, `image` and any `input` additional fields.
pub async fn update_user(auth: &Auth, meta: &RequestMeta, body: Record) -> Result<ApiResponse<Status>> {
    let current = require_session(auth, &meta.headers).await?;
    if body.contains_key("email") {
        return Err(AuthError::email_can_not_be_updated());
    }
    let mut data = user_input_fields(auth, body.clone(), false)?;
    if let Some(name) = body.get("name") {
        data.insert("name".into(), Value::String(name.as_str().ok_or_else(|| AuthError::validation("name must be a string"))?.into()));
    }
    if let Some(image) = body.get("image") {
        data.insert("image".into(), image.clone());
    }
    if data.is_empty() {
        return Err(AuthError::validation("No fields to update"));
    }
    auth.db.update_user(&current.user.id, data).await?;
    Ok(Status::ok())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePassword {
    pub new_password: String,
    pub current_password: String,
    #[serde(default)]
    pub revoke_other_sessions: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ChangePasswordResponse {
    pub token: Option<String>,
    pub user: User,
}

/// `POST /change-password`.
pub async fn change_password(auth: &Auth, meta: &RequestMeta, body: ChangePassword) -> Result<ApiResponse<ChangePasswordResponse>> {
    let current = require_session(auth, &meta.headers).await?;
    auth.check_password_length(&body.new_password)?;
    let account = auth.db.find_credential_account(&current.user.id).await?;
    let hash = account.and_then(|a| a.password).ok_or_else(AuthError::credential_account_not_found)?;
    if !auth.verify_password(&hash, &body.current_password).await {
        return Err(AuthError::invalid_password());
    }
    let new_hash = auth.hash_password(&body.new_password).await;
    auth.db.update_password(&current.user.id, &new_hash).await?;

    let mut res = ChangePasswordResponse { token: None, user: current.user.clone() };
    let mut cookies = Vec::new();
    if body.revoke_other_sessions == Some(true) {
        auth.db.delete_user_sessions(&current.user.id).await?;
        let dont_remember = crate::cookies::get_signed_cookie(&meta.headers, &auth.cookies.dont_remember, auth.secret()).is_some();
        let (session, c) = create_session(auth, &current.user, meta, dont_remember).await?;
        res.token = Some(session.token);
        cookies = c;
    }
    Ok(ApiResponse::ok(res).with_cookies(cookies))
}

/// Server-side only: give a user without a password (e.g. social sign-up) a
/// credential account.
pub async fn set_password(auth: &Auth, user_id: &str, new_password: &str) -> Result<()> {
    auth.check_password_length(new_password)?;
    if auth.db.find_credential_account(user_id).await?.is_some() {
        return Err(AuthError::bad_request("PASSWORD_ALREADY_SET", "User already has a password"));
    }
    let hash = auth.hash_password(new_password).await;
    auth.db.create_credential_account(user_id, &hash).await?;
    Ok(())
}

#[derive(Debug, Default, Deserialize)]
pub struct DeleteUser {
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default, rename = "callbackURL")]
    pub callback_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeleteUserResponse {
    pub success: bool,
    pub message: String,
}

/// `POST /delete-user`. Requires the password, or a fresh session.
pub async fn delete_user(auth: &Auth, meta: &RequestMeta, body: DeleteUser) -> Result<ApiResponse<DeleteUserResponse>> {
    if !auth.options.user.delete_user.enabled {
        return Err(AuthError::delete_user_disabled());
    }
    auth.validate_redirect(body.callback_url.as_deref())?;
    let current = require_session(auth, &meta.headers).await?;
    match &body.password {
        Some(password) => {
            let account = auth.db.find_credential_account(&current.user.id).await?;
            let hash = account.and_then(|a| a.password).ok_or_else(AuthError::credential_account_not_found)?;
            if !auth.verify_password(&hash, password).await {
                return Err(AuthError::invalid_password());
            }
        }
        None if !is_fresh(auth, &current.session) => return Err(AuthError::session_not_fresh()),
        None => {}
    }
    auth.db.delete_user(&current.user.id).await?;
    let res = ApiResponse::ok(DeleteUserResponse { success: true, message: "User deleted".into() }).with_cookies(clear_session_cookies(auth));
    Ok(match body.callback_url {
        Some(url) => res.redirect(url),
        None => res,
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeEmail {
    pub new_email: String,
    #[serde(default, rename = "callbackURL")]
    pub callback_url: Option<String>,
}

/// `POST /change-email`. Unverified emails change immediately; verified ones
/// require confirmation through a link sent to the current address.
pub async fn change_email(auth: &Auth, meta: &RequestMeta, body: ChangeEmail) -> Result<ApiResponse<Status>> {
    let opts = &auth.options.user.change_email;
    if !opts.enabled {
        return Err(AuthError::change_email_disabled());
    }
    auth.validate_redirect(body.callback_url.as_deref())?;
    let current = require_session(auth, &meta.headers).await?;
    let new_email = body.new_email.trim().to_lowercase();
    if !is_valid_email(&new_email) {
        return Err(AuthError::invalid_email());
    }
    if new_email == current.user.email {
        return Err(AuthError::email_is_the_same());
    }
    if auth.db.find_user_by_email(&new_email).await?.is_some() {
        return Err(AuthError::user_already_exists());
    }

    if !current.user.email_verified {
        let mut data = Record::new();
        data.insert("email".into(), new_email.clone().into());
        data.insert("emailVerified".into(), false.into());
        let user = auth.db.update_user(&current.user.id, data).await?;
        if auth.options.email_verification.send_verification_email.is_some() {
            super::verification::send_verification_for(auth, &user, body.callback_url.as_deref()).await?;
        }
        return Ok(Status::ok());
    }

    let Some(send) = &opts.send_change_email_verification else {
        return Err(AuthError::verification_email_disabled());
    };
    let mut claims = Map::new();
    claims.insert("email".into(), current.user.email.clone().into());
    claims.insert("updateTo".into(), new_email.clone().into());
    let token = sign_jwt(auth.secret(), claims, auth.options.email_verification.expires_in);
    let url = super::verification::verify_url(auth, &token, body.callback_url.as_deref());
    send.call(ChangeEmailVerification { user: current.user, new_email, url, token }).await;
    Ok(Status::ok())
}
