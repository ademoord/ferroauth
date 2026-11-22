//! Error type shared by every endpoint. Serialises to
//! `{ "code": "...", "message": "..." }` so clients can branch on stable codes.

use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::db::DbError;

pub type Result<T, E = AuthError> = std::result::Result<T, E>;

#[derive(Debug, Clone, thiserror::Error)]
#[error("{status} {code}: {message}")]
pub struct AuthError {
    pub status: StatusCode,
    pub code: String,
    pub message: String,
}

impl AuthError {
    pub fn new(status: StatusCode, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self { status, code: code.into(), message: message.into() }
    }

    pub fn bad_request(code: &str, message: &str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_SERVER_ERROR", message)
    }

    pub fn validation(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", message)
    }
}

macro_rules! error_codes {
    ($( $fn:ident => ($status:ident, $code:literal, $msg:literal) ),* $(,)?) => {
        impl AuthError {
            $(
                #[doc = $msg]
                pub fn $fn() -> Self { Self::new(StatusCode::$status, $code, $msg) }
            )*
        }
    };
}

error_codes! {
    user_not_found => (BAD_REQUEST, "USER_NOT_FOUND", "User not found"),
    failed_to_create_user => (UNPROCESSABLE_ENTITY, "FAILED_TO_CREATE_USER", "Failed to create user"),
    failed_to_create_session => (UNPROCESSABLE_ENTITY, "FAILED_TO_CREATE_SESSION", "Failed to create session"),
    failed_to_update_user => (INTERNAL_SERVER_ERROR, "FAILED_TO_UPDATE_USER", "Failed to update user"),
    failed_to_get_session => (BAD_REQUEST, "FAILED_TO_GET_SESSION", "Failed to get session"),
    invalid_password => (BAD_REQUEST, "INVALID_PASSWORD", "Invalid password"),
    invalid_email => (BAD_REQUEST, "INVALID_EMAIL", "Invalid email"),
    invalid_email_or_password => (UNAUTHORIZED, "INVALID_EMAIL_OR_PASSWORD", "Invalid email or password"),
    social_account_already_linked => (BAD_REQUEST, "SOCIAL_ACCOUNT_ALREADY_LINKED", "Social account already linked"),
    provider_not_found => (NOT_FOUND, "PROVIDER_NOT_FOUND", "Provider not found"),
    invalid_token => (BAD_REQUEST, "INVALID_TOKEN", "Invalid token"),
    id_token_not_supported => (BAD_REQUEST, "ID_TOKEN_NOT_SUPPORTED", "id_token not supported"),
    failed_to_get_user_info => (BAD_REQUEST, "FAILED_TO_GET_USER_INFO", "Failed to get user info"),
    user_email_not_found => (BAD_REQUEST, "USER_EMAIL_NOT_FOUND", "User email not found"),
    email_not_verified => (FORBIDDEN, "EMAIL_NOT_VERIFIED", "Email not verified"),
    password_too_short => (BAD_REQUEST, "PASSWORD_TOO_SHORT", "Password too short"),
    password_too_long => (BAD_REQUEST, "PASSWORD_TOO_LONG", "Password too long"),
    user_already_exists => (UNPROCESSABLE_ENTITY, "USER_ALREADY_EXISTS", "User already exists. Use another email."),
    email_can_not_be_updated => (BAD_REQUEST, "EMAIL_CAN_NOT_BE_UPDATED", "Email can not be updated"),
    credential_account_not_found => (BAD_REQUEST, "CREDENTIAL_ACCOUNT_NOT_FOUND", "Credential account not found"),
    session_expired => (UNAUTHORIZED, "SESSION_EXPIRED", "Session expired. Re-authenticate to perform this action."),
    session_not_fresh => (FORBIDDEN, "SESSION_NOT_FRESH", "Session is not fresh. Re-authenticate to perform this action."),
    failed_to_unlink_last_account => (BAD_REQUEST, "FAILED_TO_UNLINK_LAST_ACCOUNT", "You can't unlink your last account"),
    account_not_found => (BAD_REQUEST, "ACCOUNT_NOT_FOUND", "Account not found"),
    user_already_has_password => (BAD_REQUEST, "USER_ALREADY_HAS_PASSWORD", "User already has a password. Provide that to delete the account."),
    unauthorized => (UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized"),
    invalid_origin => (FORBIDDEN, "INVALID_ORIGIN", "Invalid origin"),
    missing_or_null_origin => (FORBIDDEN, "MISSING_OR_NULL_ORIGIN", "Missing or null Origin"),
    invalid_callback_url => (FORBIDDEN, "INVALID_CALLBACK_URL", "Invalid callbackURL"),
    too_many_requests => (TOO_MANY_REQUESTS, "TOO_MANY_REQUESTS", "Too many requests. Please try again later."),
    email_password_disabled => (BAD_REQUEST, "EMAIL_PASSWORD_DISABLED", "Email and password is not enabled"),
    sign_up_disabled => (BAD_REQUEST, "SIGN_UP_DISABLED", "Sign up is disabled"),
    reset_password_disabled => (BAD_REQUEST, "RESET_PASSWORD_DISABLED", "Reset password isn't enabled"),
    verification_email_disabled => (BAD_REQUEST, "VERIFICATION_EMAIL_NOT_ENABLED", "Verification email isn't enabled"),
    email_already_verified => (BAD_REQUEST, "EMAIL_ALREADY_VERIFIED", "Email is already verified"),
    change_email_disabled => (BAD_REQUEST, "CHANGE_EMAIL_DISABLED", "Change email is disabled"),
    delete_user_disabled => (NOT_FOUND, "DELETE_USER_DISABLED", "Delete user is disabled"),
    email_is_the_same => (BAD_REQUEST, "EMAIL_IS_THE_SAME", "Email is the same"),
}

impl From<DbError> for AuthError {
    fn from(err: DbError) -> Self {
        match err {
            DbError::UniqueViolation(_) => {
                AuthError::new(StatusCode::UNPROCESSABLE_ENTITY, "UNIQUE_VIOLATION", "A record with this value already exists")
            }
            other => {
                tracing::error!(error = %other, "database error");
                AuthError::internal("Database error")
            }
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let mut res = (self.status, Json(json!({ "code": self.code, "message": self.message }))).into_response();
        if self.status == StatusCode::TOO_MANY_REQUESTS {
            res.headers_mut().insert("x-retry-after", HeaderValue::from_static("10"));
        }
        res
    }
}
