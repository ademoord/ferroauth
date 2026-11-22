//! Email verification: `POST /send-verification-email`, `GET /verify-email`.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::session::Status;
use super::with_query;
use crate::context::Auth;
use crate::cookies::encode_uri_component;
use crate::crypto::{sign_jwt, verify_jwt, JwtError};
use crate::db::Record;
use crate::error::{AuthError, Result};
use crate::models::User;
use crate::options::VerificationEmail;
use crate::session::{create_session, get_session, ApiResponse, RequestMeta};

pub(crate) fn verify_url(auth: &Auth, token: &str, callback_url: Option<&str>) -> String {
    format!(
        "{}/verify-email?token={}&callbackURL={}",
        auth.api_url(),
        encode_uri_component(token),
        encode_uri_component(callback_url.unwrap_or("/"))
    )
}

/// Create a verification token for `user` and hand it to `send_verification_email`.
pub async fn send_verification_for(auth: &Auth, user: &User, callback_url: Option<&str>) -> Result<()> {
    let Some(send) = &auth.options.email_verification.send_verification_email else {
        return Err(AuthError::verification_email_disabled());
    };
    let mut claims = Map::new();
    claims.insert("email".into(), user.email.clone().into());
    let token = sign_jwt(auth.secret(), claims, auth.options.email_verification.expires_in);
    let url = verify_url(auth, &token, callback_url);
    send.call(VerificationEmail { user: user.clone(), url, token }).await;
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct SendVerificationEmail {
    pub email: String,
    #[serde(default, rename = "callbackURL")]
    pub callback_url: Option<String>,
}

pub async fn send_verification_email(auth: &Auth, meta: &RequestMeta, body: SendVerificationEmail) -> Result<ApiResponse<Status>> {
    if auth.options.email_verification.send_verification_email.is_none() {
        return Err(AuthError::verification_email_disabled());
    }
    auth.validate_redirect(body.callback_url.as_deref())?;
    let email = body.email.trim().to_lowercase();
    if let Some(current) = get_session(auth, &meta.headers, false).await?.data {
        if current.user.email != email {
            return Err(AuthError::bad_request("EMAIL_MISMATCH", "Email mismatch"));
        }
        if current.user.email_verified {
            return Err(AuthError::email_already_verified());
        }
        send_verification_for(auth, &current.user, body.callback_url.as_deref()).await?;
        return Ok(Status::ok());
    }
    // Do not reveal whether the account exists.
    if let Some(user) = auth.db.find_user_by_email(&email).await? {
        if !user.email_verified {
            send_verification_for(auth, &user, body.callback_url.as_deref()).await?;
        }
    }
    Ok(Status::ok())
}

#[derive(Debug, Deserialize)]
pub struct VerifyEmailQuery {
    pub token: String,
    #[serde(default, rename = "callbackURL")]
    pub callback_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct VerifyEmailResponse {
    pub status: bool,
    pub user: Option<User>,
}

fn fail(callback: Option<&str>, err: AuthError) -> Result<ApiResponse<VerifyEmailResponse>> {
    match callback {
        Some(cb) => Ok(ApiResponse::ok(VerifyEmailResponse { status: false, user: None })
            .redirect(with_query(cb, "error", &err.code.to_lowercase()))),
        None => Err(err),
    }
}

pub async fn verify_email(auth: &Auth, meta: &RequestMeta, q: VerifyEmailQuery) -> Result<ApiResponse<VerifyEmailResponse>> {
    auth.validate_redirect(q.callback_url.as_deref())?;
    let cb = q.callback_url.as_deref();
    let claims = match verify_jwt(auth.secret(), &q.token) {
        Ok(c) => c,
        Err(JwtError::Expired) => return fail(cb, AuthError::bad_request("TOKEN_EXPIRED", "Token expired")),
        Err(JwtError::Invalid) => return fail(cb, AuthError::invalid_token()),
    };
    let Some(email) = claims.get("email").and_then(Value::as_str) else { return fail(cb, AuthError::invalid_token()) };
    let Some(user) = auth.db.find_user_by_email(email).await? else { return fail(cb, AuthError::user_not_found()) };

    // Confirmed email change: move to the new address, then verify that one.
    if let Some(update_to) = claims.get("updateTo").and_then(Value::as_str) {
        if auth.db.find_user_by_email(update_to).await?.is_some() {
            return fail(cb, AuthError::user_already_exists());
        }
        let mut data = Record::new();
        data.insert("email".into(), update_to.into());
        data.insert("emailVerified".into(), false.into());
        let user = auth.db.update_user(&user.id, data).await?;
        if auth.options.email_verification.send_verification_email.is_some() {
            send_verification_for(auth, &user, cb).await?;
        }
        let res = ApiResponse::ok(VerifyEmailResponse { status: true, user: Some(auth.public_user(user)) });
        return Ok(match cb {
            Some(cb) => res.redirect(cb),
            None => res,
        });
    }

    let user = if user.email_verified {
        user
    } else {
        let mut data = Record::new();
        data.insert("emailVerified".into(), true.into());
        auth.db.update_user(&user.id, data).await?
    };
    let mut res = ApiResponse::ok(VerifyEmailResponse { status: true, user: None });
    if auth.options.email_verification.auto_sign_in_after_verification {
        let (_, cookies) = create_session(auth, &user, meta, false).await?;
        res = res.with_cookies(cookies);
    }
    Ok(match cb {
        Some(cb) => res.redirect(cb),
        None => res,
    })
}
