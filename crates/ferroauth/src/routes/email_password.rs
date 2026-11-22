//! `POST /sign-up/email`, `POST /sign-in/email`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::is_valid_email;
use crate::context::Auth;
use crate::db::Record;
use crate::error::{AuthError, Result};
use crate::models::User;
use crate::schema::USER;
use crate::session::{create_session, ApiResponse, RequestMeta};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignUpEmail {
    pub name: String,
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default, rename = "callbackURL")]
    pub callback_url: Option<String>,
    #[serde(default)]
    pub remember_me: Option<bool>,
    /// Additional user fields (from `additional_fields` or plugins) marked `input`.
    #[serde(flatten)]
    pub additional: Record,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignUpResponse {
    pub token: Option<String>,
    pub user: User,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInEmail {
    pub email: String,
    pub password: String,
    #[serde(default, rename = "callbackURL")]
    pub callback_url: Option<String>,
    #[serde(default)]
    pub remember_me: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignInResponse {
    pub redirect: bool,
    pub token: String,
    pub url: Option<String>,
    pub user: User,
}

/// Keep only user fields the schema marks as client-settable; error on
/// missing required ones.
pub(crate) fn user_input_fields(auth: &Auth, input: Record, creating: bool) -> Result<Record> {
    let table = auth.schema.table(USER).expect("user table");
    let mut out = Record::new();
    for field in table.fields.iter().filter(|f| f.input) {
        match input.get(&field.name) {
            Some(v) if !v.is_null() => {
                out.insert(field.name.clone(), v.clone());
            }
            _ if creating && field.required => {
                return Err(AuthError::validation(format!("{} is required", field.name)));
            }
            Some(_) => {
                out.insert(field.name.clone(), Value::Null);
            }
            None => {}
        }
    }
    Ok(out)
}

pub async fn sign_up_email(auth: &Auth, meta: &RequestMeta, body: SignUpEmail) -> Result<ApiResponse<SignUpResponse>> {
    let opts = &auth.options.email_and_password;
    if !opts.enabled {
        return Err(AuthError::email_password_disabled());
    }
    if opts.disable_sign_up {
        return Err(AuthError::sign_up_disabled());
    }
    auth.validate_redirect(body.callback_url.as_deref())?;
    let email = body.email.trim().to_lowercase();
    if !is_valid_email(&email) {
        return Err(AuthError::invalid_email());
    }
    auth.check_password_length(&body.password)?;
    if auth.db.find_user_by_email(&email).await?.is_some() {
        return Err(AuthError::user_already_exists());
    }

    let mut data = user_input_fields(auth, body.additional, true)?;
    data.insert("name".into(), body.name.into());
    data.insert("email".into(), email.into());
    data.insert("image".into(), body.image.map(Value::String).unwrap_or(Value::Null));
    let hash = auth.hash_password(&body.password).await;
    let user = auth.db.create_user(data).await.map_err(|e| {
        if e.code == "UNIQUE_VIOLATION" {
            AuthError::user_already_exists()
        } else {
            e
        }
    })?;
    auth.db.create_credential_account(&user.id, &hash).await?;

    let ev = &auth.options.email_verification;
    if (ev.send_on_sign_up || opts.require_email_verification)
        && ev.send_verification_email.is_some() {
            super::verification::send_verification_for(auth, &user, body.callback_url.as_deref()).await?;
        }

    if !opts.auto_sign_in || opts.require_email_verification {
        return Ok(ApiResponse::ok(SignUpResponse { token: None, user: auth.public_user(user) }));
    }
    let (session, cookies) = create_session(auth, &user, meta, body.remember_me == Some(false)).await?;
    Ok(ApiResponse::ok(SignUpResponse { token: Some(session.token), user: auth.public_user(user) }).with_cookies(cookies))
}

pub async fn sign_in_email(auth: &Auth, meta: &RequestMeta, body: SignInEmail) -> Result<ApiResponse<SignInResponse>> {
    if !auth.options.email_and_password.enabled {
        return Err(AuthError::email_password_disabled());
    }
    auth.validate_redirect(body.callback_url.as_deref())?;
    let email = body.email.trim().to_lowercase();
    if !is_valid_email(&email) {
        return Err(AuthError::invalid_email());
    }
    let user = auth.db.find_user_by_email(&email).await?;
    sign_in_with_password(auth, meta, user, &body.password, body.remember_me, body.callback_url).await
}

/// Shared password sign-in flow (also used by the username plugin).
pub async fn sign_in_with_password(
    auth: &Auth,
    meta: &RequestMeta,
    user: Option<User>,
    password: &str,
    remember_me: Option<bool>,
    callback_url: Option<String>,
) -> Result<ApiResponse<SignInResponse>> {
    let Some(user) = user else {
        // Equalise timing with the "user exists" path.
        let _ = auth.hash_password(password).await;
        return Err(AuthError::invalid_email_or_password());
    };
    let account = auth.db.find_credential_account(&user.id).await?;
    let Some(hash) = account.and_then(|a| a.password) else {
        let _ = auth.hash_password(password).await;
        return Err(AuthError::invalid_email_or_password());
    };
    if !auth.verify_password(&hash, password).await {
        return Err(AuthError::invalid_email_or_password());
    }
    if auth.options.email_and_password.require_email_verification && !user.email_verified {
        let ev = &auth.options.email_verification;
        if ev.send_on_sign_in && ev.send_verification_email.is_some() {
            super::verification::send_verification_for(auth, &user, callback_url.as_deref()).await?;
        }
        return Err(AuthError::email_not_verified());
    }
    let (session, cookies) = create_session(auth, &user, meta, remember_me == Some(false)).await?;
    Ok(ApiResponse::ok(SignInResponse {
        redirect: callback_url.is_some(),
        token: session.token,
        url: callback_url,
        user: auth.public_user(user),
    })
    .with_cookies(cookies))
}
