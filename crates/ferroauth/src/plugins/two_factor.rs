//! Two-factor authentication plugin.
//!
//! - **TOTP** (authenticator apps), **OTP** (codes sent by email/SMS through a
//!   callback) and single-use **backup codes**.
//! - Credential sign-ins (`/sign-in/email`, `/sign-in/username`) of users with
//!   2FA enabled answer `{ twoFactorRedirect: true, twoFactorMethods }` instead
//!   of creating a session. A signed `two_factor` cookie carries the pending
//!   challenge to the `/two-factor/verify-*` endpoints.
//! - "Trust this device" for 30 days, revocable server-side.
//! - Brute-force protection: 5 attempts per challenge, and an account lock
//!   after 10 consecutive failures (15 minutes).
//!
//! Data lives in the `twoFactor` table; TOTP secrets and backup codes are
//! encrypted with XChaCha20-Poly1305 under the auth secret.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::State;
use axum::http::header::{CONTENT_TYPE, SET_COOKIE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Router};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{Plugin, RequestInfo};
use crate::context::Auth;
use crate::cookies::{get_signed_cookie, parse_set_cookie};
use crate::crypto::{
    base32_decode, base64url, constant_time_eq, otpauth_url, random_string_from, sha256, symmetric_decrypt,
    symmetric_encrypt, totp_now, verify_totp, DIGITS, URL_SAFE_ALPHABET,
};
use crate::db::{Record, Where};
use crate::error::{AuthError, Result};
use crate::models::{from_record, ts, ts_value, Session, SessionWithUser, Timestamp, User};
use crate::options::{Callback, RateLimitRule};
use crate::schema::{Field, Schema, Table, USER};
use crate::session::{create_session, get_session, require_session, session_cookies, ApiResponse, JsonBody, RequestMeta};

pub const TABLE: &str = "twoFactor";
const SIGN_IN_PATHS: [&str; 3] = ["/sign-in/email", "/sign-in/username", "/sign-in/phone-number"];
const ATTEMPTS_PER_CHALLENGE: u32 = 5;

// ---- options -----------------------------------------------------------------------------

/// Payload for `otp.send_otp`.
#[derive(Debug, Clone)]
pub struct TwoFactorOtp {
    pub user: User,
    pub otp: String,
}

#[derive(Debug, Clone)]
pub struct TotpOptions {
    pub digits: u32,
    /// Seconds.
    pub period: u64,
    pub disable: bool,
}

impl Default for TotpOptions {
    fn default() -> Self {
        Self { digits: 6, period: 30, disable: false }
    }
}

/// How OTP codes are kept in the verification table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OtpStorage {
    #[default]
    Plain,
    /// base64url(SHA-256(code)).
    Hashed,
    Encrypted,
}

#[derive(Debug, Clone)]
pub struct OtpOptions {
    /// Delivers the code (email, SMS…). OTP is unavailable without it.
    pub send_otp: Option<Callback<TwoFactorOtp>>,
    /// Minutes. Default 3.
    pub period_minutes: i64,
    pub digits: usize,
    pub allowed_attempts: u32,
    pub storage: OtpStorage,
}

impl Default for OtpOptions {
    fn default() -> Self {
        Self { send_otp: None, period_minutes: 3, digits: 6, allowed_attempts: 5, storage: OtpStorage::Plain }
    }
}

#[derive(Debug, Clone)]
pub struct BackupCodeOptions {
    pub amount: usize,
    pub length: usize,
}

impl Default for BackupCodeOptions {
    fn default() -> Self {
        Self { amount: 10, length: 10 }
    }
}

#[derive(Debug, Clone)]
pub struct AccountLockoutOptions {
    pub enabled: bool,
    pub max_failed_attempts: i64,
    /// Seconds. Default 15 minutes.
    pub duration_seconds: i64,
}

impl Default for AccountLockoutOptions {
    fn default() -> Self {
        Self { enabled: true, max_failed_attempts: 10, duration_seconds: 900 }
    }
}

#[derive(Debug, Clone)]
pub struct TwoFactorOptions {
    /// Issuer shown in authenticator apps. Default: `app_name`.
    pub issuer: Option<String>,
    /// Turn 2FA on at `/two-factor/enable` without first verifying a TOTP code.
    pub skip_verification_on_enable: bool,
    /// Users without a password (e.g. social sign-up) may manage 2FA without one.
    pub allow_passwordless: bool,
    /// Seconds. Default 30 days.
    pub trust_device_max_age: i64,
    /// Seconds the pending sign-in challenge is valid. Default 10 minutes.
    pub two_factor_cookie_max_age: i64,
    pub totp: TotpOptions,
    pub otp: OtpOptions,
    pub backup_codes: BackupCodeOptions,
    pub account_lockout: AccountLockoutOptions,
}

impl Default for TwoFactorOptions {
    fn default() -> Self {
        Self {
            issuer: None,
            skip_verification_on_enable: false,
            allow_passwordless: false,
            trust_device_max_age: 30 * 24 * 60 * 60,
            two_factor_cookie_max_age: 600,
            totp: TotpOptions::default(),
            otp: OtpOptions::default(),
            backup_codes: BackupCodeOptions::default(),
            account_lockout: AccountLockoutOptions::default(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TwoFactor {
    opts: Arc<TwoFactorOptions>,
}

impl TwoFactor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_options(opts: TwoFactorOptions) -> Self {
        Self { opts: Arc::new(opts) }
    }
}

type Opts = Arc<TwoFactorOptions>;

// ---- errors ------------------------------------------------------------------------------

fn tf_error(status: StatusCode, code: &str) -> AuthError {
    let message = match code {
        "OTP_NOT_CONFIGURED" => "OTP is not available",
        "OTP_HAS_EXPIRED" => "OTP has expired",
        "TOTP_NOT_ENABLED" => "TOTP not enabled",
        "TOTP_ALREADY_ENABLED" => "TOTP is already enabled",
        "TOTP_NOT_CONFIGURED" => "TOTP is not available",
        "TWO_FACTOR_NOT_ENABLED" => "Two factor isn't enabled",
        "BACKUP_CODES_NOT_ENABLED" => "Backup codes aren't enabled",
        "INVALID_BACKUP_CODE" => "Invalid backup code",
        "INVALID_CODE" => "Invalid code",
        "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE" => "Too many attempts. Please request a new code.",
        "ACCOUNT_TEMPORARILY_LOCKED" => {
            "Too many failed verification attempts. Your account is temporarily locked. Please try again later."
        }
        "INVALID_TWO_FACTOR_COOKIE" => "Invalid two factor cookie",
        _ => code,
    };
    AuthError::new(status, code, message)
}

fn bad(code: &str) -> AuthError {
    tf_error(StatusCode::BAD_REQUEST, code)
}

fn unauthorized(code: &str) -> AuthError {
    tf_error(StatusCode::UNAUTHORIZED, code)
}

// ---- storage -----------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TwoFactorRecord {
    id: String,
    secret: String,
    backup_codes: String,
    #[serde(default)]
    verified: Option<bool>,
    #[serde(default)]
    failed_verification_count: Option<i64>,
    #[serde(default, with = "ts::option")]
    locked_until: Option<Timestamp>,
}

async fn find_record(auth: &Auth, user_id: &str) -> Result<Option<TwoFactorRecord>> {
    auth.raw_adapter().find_one(TABLE, &[Where::eq("userId", user_id)]).await?.map(from_record).transpose()
}

async fn update_record(auth: &Auth, id: &str, data: Record) -> Result<()> {
    auth.db.update(TABLE, &[Where::eq("id", id)], data).await?;
    Ok(())
}

fn two_factor_enabled(user: &User) -> bool {
    user.extra.get("twoFactorEnabled") == Some(&Value::Bool(true))
}

async fn set_two_factor_enabled(auth: &Auth, user_id: &str, enabled: bool) -> Result<User> {
    let mut d = Record::new();
    d.insert("twoFactorEnabled".into(), enabled.into());
    auth.db.update_user(user_id, d).await
}

/// Decrypt a stored TOTP secret into the HMAC key bytes. Secrets imported
/// from other systems may be stored as `base32:<secret>`.
fn decrypt_secret(auth: &Auth, stored: &str) -> Result<Vec<u8>> {
    let plain = symmetric_decrypt(auth.secret(), stored).ok_or_else(|| AuthError::internal("cannot decrypt TOTP secret"))?;
    match plain.strip_prefix("base32:") {
        Some(b32) => base32_decode(b32).ok_or_else(|| AuthError::internal("invalid base32 TOTP secret")),
        None => Ok(plain.into_bytes()),
    }
}

fn generate_backup_codes(opts: &TwoFactorOptions) -> Vec<String> {
    const ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    (0..opts.backup_codes.amount)
        .map(|_| {
            let code = random_string_from(opts.backup_codes.length, ALNUM);
            let split = code.len().min(5);
            format!("{}-{}", &code[..split], &code[split..])
        })
        .collect()
}

fn encrypt_codes(auth: &Auth, codes: &[String]) -> String {
    symmetric_encrypt(auth.secret(), &serde_json::to_string(codes).expect("serializable"))
}

fn decrypt_codes(auth: &Auth, stored: &str) -> Option<Vec<String>> {
    serde_json::from_str(&symmetric_decrypt(auth.secret(), stored)?).ok()
}

async fn check_password(auth: &Auth, opts: &TwoFactorOptions, user_id: &str, password: Option<&str>) -> Result<()> {
    let account = auth.db.find_credential_account(user_id).await?;
    let hash = account.and_then(|a| a.password);
    let Some(hash) = hash else {
        // No password to check: only allowed when explicitly enabled.
        return if opts.allow_passwordless { Ok(()) } else { Err(AuthError::invalid_password()) };
    };
    match password {
        Some(p) if auth.verify_password(&hash, p).await => Ok(()),
        _ => Err(AuthError::invalid_password()),
    }
}

fn totp_uri(auth: &Auth, opts: &TwoFactorOptions, issuer: Option<&str>, account: &str, secret: &[u8]) -> String {
    let issuer = issuer.or(opts.issuer.as_deref()).unwrap_or(&auth.options.app_name);
    otpauth_url(issuer, account, secret, opts.totp.digits, opts.totp.period)
}

/// Replace the current session with a fresh one (after 2FA state changes).
async fn rotate_session(auth: &Auth, meta: &RequestMeta, current: &Session, user: &User) -> Result<(Session, Vec<String>)> {
    let dont_remember = get_signed_cookie(&meta.headers, &auth.cookies.dont_remember, auth.secret()).is_some();
    let created = create_session(auth, user, meta, dont_remember).await?;
    auth.db.delete_session(&current.token).await?;
    Ok(created)
}

// ---- trusted devices ---------------------------------------------------------------------

fn trust_token(auth: &Auth, user_id: &str, identifier: &str) -> String {
    base64url(&crate::crypto::hmac_sha256(auth.secret().as_bytes(), format!("{user_id}!{identifier}").as_bytes()))
}

/// Record a trusted device and return its cookie.
async fn trust_device_cookie(auth: &Auth, opts: &TwoFactorOptions, user_id: &str) -> Result<String> {
    let identifier = format!("trust-device-{}", random_string_from(32, URL_SAFE_ALPHABET));
    let max_age = opts.trust_device_max_age;
    auth.db.create_verification(&identifier, user_id, Utc::now() + Duration::seconds(max_age)).await?;
    let value = format!("{}!{identifier}", trust_token(auth, user_id, &identifier));
    Ok(auth.cookies.set_signed(&auth.cookies.name("trust_device"), &value, auth.secret(), Some(max_age)))
}

/// Whether the request carries a valid trust-device cookie for `user_id`.
/// Returns `(trusted, identifier from the cookie)`.
async fn check_trusted_device(auth: &Auth, headers: &axum::http::HeaderMap, user_id: &str) -> Result<(bool, Option<String>)> {
    let Some(value) = get_signed_cookie(headers, &auth.cookies.name("trust_device"), auth.secret()) else {
        return Ok((false, None));
    };
    let Some((token, identifier)) = value.split_once('!') else { return Ok((false, Some(String::new()))) };
    if !constant_time_eq(token.as_bytes(), trust_token(auth, user_id, identifier).as_bytes()) {
        return Ok((false, Some(identifier.to_string())));
    }
    let record = auth.db.find_verification(identifier).await?;
    let trusted = record.is_some_and(|v| v.value == user_id && v.expires_at > Utc::now());
    Ok((trusted, Some(identifier.to_string())))
}

// ---- challenges --------------------------------------------------------------------------

/// Who is being verified: a user mid sign-in (two_factor cookie), or a
/// signed-in user (e.g. confirming TOTP setup).
enum Challenge {
    SignIn { user: User, identifier: String, expires_at: Timestamp },
    Session(SessionWithUser),
}

impl Challenge {
    fn user(&self) -> &User {
        match self {
            Challenge::SignIn { user, .. } => user,
            Challenge::Session(s) => &s.user,
        }
    }

    fn is_sign_in(&self) -> bool {
        matches!(self, Challenge::SignIn { .. })
    }

    /// Scopes OTP codes to this challenge.
    fn key(&self) -> String {
        match self {
            Challenge::SignIn { identifier, .. } => identifier.clone(),
            Challenge::Session(s) => format!("{}!{}", s.user.id, s.session.id),
        }
    }
}

async fn challenge(auth: &Auth, meta: &RequestMeta) -> Result<Challenge> {
    if let Some(s) = get_session(auth, &meta.headers, false).await?.data {
        return Ok(Challenge::Session(s));
    }
    let identifier = get_signed_cookie(&meta.headers, &auth.cookies.name("two_factor"), auth.secret())
        .ok_or_else(|| unauthorized("INVALID_TWO_FACTOR_COOKIE"))?;
    let v = auth.db.find_verification(&identifier).await?.filter(|v| v.expires_at > Utc::now());
    let v = v.ok_or_else(|| unauthorized("INVALID_TWO_FACTOR_COOKIE"))?;
    let user = auth.db.find_user_by_id(&v.value).await?.ok_or_else(|| unauthorized("INVALID_TWO_FACTOR_COOKIE"))?;
    Ok(Challenge::SignIn { user, identifier, expires_at: v.expires_at })
}

#[derive(Debug, Serialize)]
pub struct Verified {
    pub token: Option<String>,
    pub user: User,
}

/// The challenge passed: finish the sign-in (create the session) or, for a
/// signed-in user, just report success.
async fn complete(auth: &Auth, opts: &TwoFactorOptions, meta: &RequestMeta, ch: Challenge, trust_device: bool) -> Result<ApiResponse<Verified>> {
    match ch {
        Challenge::Session(s) => Ok(ApiResponse::ok(Verified { token: Some(s.session.token), user: auth.public_user(s.user) })),
        Challenge::SignIn { user, identifier, .. } => {
            let consumed = auth.db.consume_verification(&identifier).await?;
            if consumed.is_none_or(|v| v.value != user.id) {
                return Err(unauthorized("INVALID_TWO_FACTOR_COOKIE"));
            }
            auth.db.delete_verifications_by_identifier(&format!("2fa-attempts-{identifier}")).await?;
            let dont_remember = get_signed_cookie(&meta.headers, &auth.cookies.dont_remember, auth.secret()).is_some();
            let (session, _) = create_session(auth, &user, meta, dont_remember).await?;
            let mut cookies = session_cookies(auth, &session, dont_remember);
            cookies.push(auth.cookies.clear(&auth.cookies.name("two_factor")));
            if trust_device {
                cookies.push(trust_device_cookie(auth, opts, &user.id).await?);
                cookies.push(auth.cookies.clear(&auth.cookies.dont_remember));
            }
            Ok(ApiResponse::ok(Verified { token: Some(session.token), user: auth.public_user(user) }).with_cookies(cookies))
        }
    }
}

/// Per-challenge attempt budget for sign-in challenges.
struct Attempt {
    identifier: String,
    count: u32,
    expires_at: Timestamp,
}

impl Attempt {
    async fn rearm(&self, auth: &Auth, count: u32) {
        let _ = auth.db.create_verification(&self.identifier, &count.to_string(), self.expires_at).await;
    }
    async fn record_failure(&self, auth: &Auth) {
        self.rearm(auth, self.count + 1).await
    }
    async fn restore(&self, auth: &Auth) {
        self.rearm(auth, self.count).await
    }
}

async fn begin_attempt(auth: &Auth, ch: &Challenge) -> Result<Option<Attempt>> {
    let Challenge::SignIn { identifier, expires_at, .. } = ch else { return Ok(None) };
    let attempts_id = format!("2fa-attempts-{identifier}");
    let consumed = auth.db.consume_verification(&attempts_id).await?.ok_or_else(|| unauthorized("INVALID_TWO_FACTOR_COOKIE"))?;
    let count = consumed.value.parse::<u32>().unwrap_or(ATTEMPTS_PER_CHALLENGE);
    if count >= ATTEMPTS_PER_CHALLENGE {
        auth.db.consume_verification(identifier).await?;
        return Err(bad("TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE"));
    }
    Ok(Some(Attempt { identifier: attempts_id, count, expires_at: *expires_at }))
}

// ---- account lockout (NIST SP 800-63B §5.2.2) ---------------------------------------------

async fn assert_not_locked(auth: &Auth, opts: &TwoFactorOptions, rec: &TwoFactorRecord) -> Result<()> {
    if !opts.account_lockout.enabled {
        return Ok(());
    }
    match rec.locked_until {
        Some(t) if t > Utc::now() => Err(tf_error(StatusCode::TOO_MANY_REQUESTS, "ACCOUNT_TEMPORARILY_LOCKED")),
        Some(_) => reset_failures(auth, opts, rec).await,
        None => Ok(()),
    }
}

async fn record_failure(auth: &Auth, opts: &TwoFactorOptions, rec: &TwoFactorRecord) -> Result<()> {
    let lockout = &opts.account_lockout;
    if !lockout.enabled {
        return Ok(());
    }
    // Re-read so concurrent failures in other requests are counted.
    let current = find_record_by_id(auth, &rec.id).await?.unwrap_or_else(|| rec.clone());
    let count = current.failed_verification_count.unwrap_or(0) + 1;
    let mut d = Record::new();
    d.insert("failedVerificationCount".into(), count.into());
    if count >= lockout.max_failed_attempts {
        d.insert("lockedUntil".into(), ts_value(&(Utc::now() + Duration::seconds(lockout.duration_seconds))));
    }
    update_record(auth, &rec.id, d).await
}

async fn reset_failures(auth: &Auth, opts: &TwoFactorOptions, rec: &TwoFactorRecord) -> Result<()> {
    if !opts.account_lockout.enabled {
        return Ok(());
    }
    let mut d = Record::new();
    d.insert("failedVerificationCount".into(), 0.into());
    d.insert("lockedUntil".into(), Value::Null);
    update_record(auth, &rec.id, d).await
}

async fn find_record_by_id(auth: &Auth, id: &str) -> Result<Option<TwoFactorRecord>> {
    auth.raw_adapter().find_one(TABLE, &[Where::eq("id", id)]).await?.map(from_record).transpose()
}

// ---- endpoints ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PasswordBody {
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EnableBody {
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyBody {
    pub code: String,
    #[serde(default)]
    pub trust_device: Option<bool>,
    #[serde(default)]
    pub disable_session: Option<bool>,
}

/// `POST /two-factor/enable` → `{ method, totpURI, backupCodes }` (TOTP) or `{ method: "otp" }`.
pub async fn enable(auth: &Auth, opts: &TwoFactorOptions, meta: &RequestMeta, body: EnableBody) -> Result<ApiResponse<Value>> {
    let current = require_session(auth, &meta.headers).await?;
    check_password(auth, opts, &current.user.id, body.password.as_deref()).await?;
    match body.method.as_deref().unwrap_or("totp") {
        "otp" => {
            if opts.otp.send_otp.is_none() {
                return Err(bad("OTP_NOT_CONFIGURED"));
            }
            let user = set_two_factor_enabled(auth, &current.user.id, true).await?;
            let (_, cookies) = rotate_session(auth, meta, &current.session, &user).await?;
            Ok(ApiResponse::ok(json!({ "method": "otp" })).with_cookies(cookies))
        }
        "totp" => {
            if opts.totp.disable {
                return Err(bad("TOTP_NOT_CONFIGURED"));
            }
            let existing = find_record(auth, &current.user.id).await?;
            if existing.as_ref().is_some_and(|r| r.verified != Some(false)) {
                return Err(bad("TOTP_ALREADY_ENABLED"));
            }
            let codes = generate_backup_codes(opts);
            let secret = random_string_from(32, URL_SAFE_ALPHABET);
            let mut cookies = Vec::new();
            if opts.skip_verification_on_enable {
                let user = set_two_factor_enabled(auth, &current.user.id, true).await?;
                cookies = rotate_session(auth, meta, &current.session, &user).await?.1;
            }
            let mut data = Record::new();
            data.insert("secret".into(), symmetric_encrypt(auth.secret(), &secret).into());
            data.insert("backupCodes".into(), encrypt_codes(auth, &codes).into());
            data.insert("verified".into(), opts.skip_verification_on_enable.into());
            match existing {
                Some(r) => update_record(auth, &r.id, data).await?,
                None => {
                    data.insert("userId".into(), current.user.id.clone().into());
                    auth.db.create(TABLE, data).await?;
                }
            }
            let uri = totp_uri(auth, opts, body.issuer.as_deref(), &current.user.email, secret.as_bytes());
            Ok(ApiResponse::ok(json!({ "method": "totp", "totpURI": uri, "backupCodes": codes })).with_cookies(cookies))
        }
        _ => Err(AuthError::validation("method must be \"totp\" or \"otp\"")),
    }
}

/// `POST /two-factor/disable` → `{ status: true }`.
pub async fn disable(auth: &Auth, opts: &TwoFactorOptions, meta: &RequestMeta, body: PasswordBody) -> Result<ApiResponse<Value>> {
    let current = require_session(auth, &meta.headers).await?;
    check_password(auth, opts, &current.user.id, body.password.as_deref()).await?;
    let user = set_two_factor_enabled(auth, &current.user.id, false).await?;
    auth.raw_adapter().delete_many(TABLE, &[Where::eq("userId", user.id.clone())]).await?;
    let (_, mut cookies) = rotate_session(auth, meta, &current.session, &user).await?;
    if let Some(value) = get_signed_cookie(&meta.headers, &auth.cookies.name("trust_device"), auth.secret()) {
        if let Some((_, identifier)) = value.split_once('!') {
            auth.db.delete_verifications_by_identifier(identifier).await?;
        }
        cookies.push(auth.cookies.clear(&auth.cookies.name("trust_device")));
    }
    Ok(ApiResponse::ok(json!({ "status": true })).with_cookies(cookies))
}

/// `POST /two-factor/get-totp-uri` → `{ totpURI }`.
pub async fn get_totp_uri(auth: &Auth, opts: &TwoFactorOptions, meta: &RequestMeta, body: PasswordBody) -> Result<ApiResponse<Value>> {
    if opts.totp.disable {
        return Err(bad("TOTP_NOT_CONFIGURED"));
    }
    let current = require_session(auth, &meta.headers).await?;
    let rec = find_record(auth, &current.user.id).await?.ok_or_else(|| bad("TOTP_NOT_ENABLED"))?;
    check_password(auth, opts, &current.user.id, body.password.as_deref()).await?;
    let secret = decrypt_secret(auth, &rec.secret)?;
    Ok(ApiResponse::ok(json!({ "totpURI": totp_uri(auth, opts, None, &current.user.email, &secret) })))
}

/// `POST /two-factor/verify-totp` `{ code, trustDevice? }` → `{ token, user }`.
/// Completes a pending sign-in, or confirms TOTP setup for a signed-in user.
pub async fn verify_totp_endpoint(auth: &Auth, opts: &TwoFactorOptions, meta: &RequestMeta, body: VerifyBody) -> Result<ApiResponse<Verified>> {
    if opts.totp.disable {
        return Err(bad("TOTP_NOT_CONFIGURED"));
    }
    let mut ch = challenge(auth, meta).await?;
    let user = ch.user().clone();
    let rec = find_record(auth, &user.id).await?.ok_or_else(|| bad("TOTP_NOT_ENABLED"))?;
    if ch.is_sign_in() {
        if rec.verified == Some(false) {
            return Err(bad("TOTP_NOT_ENABLED"));
        }
        assert_not_locked(auth, opts, &rec).await?;
    }
    let attempt = begin_attempt(auth, &ch).await?;
    let secret = match decrypt_secret(auth, &rec.secret) {
        Ok(s) => s,
        Err(e) => {
            if let Some(a) = &attempt {
                a.restore(auth).await;
            }
            return Err(e);
        }
    };
    if !verify_totp(&secret, body.code.trim(), opts.totp.period, opts.totp.digits, 1) {
        if let Some(a) = &attempt {
            a.record_failure(auth).await;
        }
        if ch.is_sign_in() {
            record_failure(auth, opts, &rec).await?;
        }
        return Err(unauthorized("INVALID_CODE"));
    }
    if ch.is_sign_in() {
        reset_failures(auth, opts, &rec).await?;
    }

    let mut cookies = Vec::new();
    if rec.verified != Some(true) {
        // First successful code after `enable`: turn 2FA on.
        if let Challenge::Session(current) = &ch {
            if !two_factor_enabled(&user) {
                let updated = set_two_factor_enabled(auth, &user.id, true).await?;
                let (session, c) = rotate_session(auth, meta, &current.session, &updated).await?;
                cookies = c;
                ch = Challenge::Session(SessionWithUser { session, user: updated });
            }
        }
        let mut d = Record::new();
        d.insert("verified".into(), true.into());
        update_record(auth, &rec.id, d).await?;
    }
    Ok(complete(auth, opts, meta, ch, body.trust_device == Some(true)).await?.with_cookies(cookies))
}

fn hash_otp(code: &str) -> String {
    base64url(&sha256(code.as_bytes()))
}

/// `POST /two-factor/send-otp` → `{ status: true }`; the code goes to `otp.send_otp`.
pub async fn send_otp(auth: &Auth, opts: &TwoFactorOptions, meta: &RequestMeta) -> Result<ApiResponse<Value>> {
    let Some(send) = &opts.otp.send_otp else { return Err(bad("OTP_NOT_CONFIGURED")) };
    let ch = challenge(auth, meta).await?;
    let code = random_string_from(opts.otp.digits, DIGITS);
    let stored = match opts.otp.storage {
        OtpStorage::Plain => code.clone(),
        OtpStorage::Hashed => hash_otp(&code),
        OtpStorage::Encrypted => symmetric_encrypt(auth.secret(), &code),
    };
    let identifier = format!("2fa-otp-{}", ch.key());
    auth.db.delete_verifications_by_identifier(&identifier).await?;
    let expires = Utc::now() + Duration::minutes(opts.otp.period_minutes);
    auth.db.create_verification(&identifier, &format!("{stored}:0"), expires).await?;
    send.call(TwoFactorOtp { user: ch.user().clone(), otp: code }).await;
    Ok(ApiResponse::ok(json!({ "status": true })))
}

/// `POST /two-factor/verify-otp` `{ code, trustDevice? }` → `{ token, user }`.
pub async fn verify_otp(auth: &Auth, opts: &TwoFactorOptions, meta: &RequestMeta, body: VerifyBody) -> Result<ApiResponse<Verified>> {
    let ch = challenge(auth, meta).await?;
    let rec = if ch.is_sign_in() { find_record(auth, &ch.user().id).await? } else { None };
    if let Some(rec) = &rec {
        assert_not_locked(auth, opts, rec).await?;
    }
    let identifier = format!("2fa-otp-{}", ch.key());
    let consumed = auth.db.consume_verification(&identifier).await?.filter(|v| v.expires_at > Utc::now());
    let consumed = consumed.ok_or_else(|| bad("OTP_HAS_EXPIRED"))?;
    let (stored, counter) = consumed.value.rsplit_once(':').unwrap_or((&consumed.value, "0"));
    let attempts: u32 = counter.parse().unwrap_or(0);
    if attempts >= opts.otp.allowed_attempts {
        return Err(bad("TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE"));
    }
    let code = body.code.trim();
    let matches = match opts.otp.storage {
        OtpStorage::Plain => constant_time_eq(stored.as_bytes(), code.as_bytes()),
        OtpStorage::Hashed => constant_time_eq(stored.as_bytes(), hash_otp(code).as_bytes()),
        OtpStorage::Encrypted => symmetric_decrypt(auth.secret(), stored).is_some_and(|s| constant_time_eq(s.as_bytes(), code.as_bytes())),
    };
    if !matches {
        auth.db.create_verification(&identifier, &format!("{stored}:{}", attempts + 1), consumed.expires_at).await?;
        if let Some(rec) = &rec {
            record_failure(auth, opts, rec).await?;
        }
        return Err(unauthorized("INVALID_CODE"));
    }
    if let Some(rec) = &rec {
        reset_failures(auth, opts, rec).await?;
    }
    if !two_factor_enabled(ch.user()) {
        // Verifying an OTP while signed in turns OTP-based 2FA on.
        let Challenge::Session(current) = &ch else { return Err(AuthError::failed_to_create_session()) };
        let updated = set_two_factor_enabled(auth, &current.user.id, true).await?;
        let (session, cookies) = rotate_session(auth, meta, &current.session, &updated).await?;
        return Ok(ApiResponse::ok(Verified { token: Some(session.token), user: auth.public_user(updated) }).with_cookies(cookies));
    }
    complete(auth, opts, meta, ch, body.trust_device == Some(true)).await
}

/// `POST /two-factor/verify-backup-code` `{ code, trustDevice?, disableSession? }` → `{ token, user }`.
/// Each backup code works once.
pub async fn verify_backup_code(auth: &Auth, opts: &TwoFactorOptions, meta: &RequestMeta, body: VerifyBody) -> Result<ApiResponse<Verified>> {
    let ch = challenge(auth, meta).await?;
    let rec = find_record(auth, &ch.user().id).await?.ok_or_else(|| bad("BACKUP_CODES_NOT_ENABLED"))?;
    if ch.is_sign_in() {
        assert_not_locked(auth, opts, &rec).await?;
    }
    let attempt = begin_attempt(auth, &ch).await?;
    let Some(codes) = decrypt_codes(auth, &rec.backup_codes) else {
        if let Some(a) = &attempt {
            a.restore(auth).await;
        }
        return Err(AuthError::internal("cannot decrypt backup codes"));
    };
    let code = body.code.trim();
    if !codes.iter().any(|c| constant_time_eq(c.as_bytes(), code.as_bytes())) {
        if let Some(a) = &attempt {
            a.record_failure(auth).await;
        }
        if ch.is_sign_in() {
            record_failure(auth, opts, &rec).await?;
        }
        return Err(unauthorized("INVALID_BACKUP_CODE"));
    }
    let remaining: Vec<String> = codes.into_iter().filter(|c| c != code).collect();
    let mut d = Record::new();
    d.insert("backupCodes".into(), encrypt_codes(auth, &remaining).into());
    // Compare-and-swap so the same code can't be redeemed twice concurrently.
    let swapped = auth.db.update(TABLE, &[Where::eq("id", rec.id.clone()), Where::eq("backupCodes", rec.backup_codes.clone())], d).await?;
    if swapped.is_none() {
        return Err(AuthError::new(StatusCode::CONFLICT, "CONFLICT", "Failed to verify backup code. Please try again."));
    }
    if ch.is_sign_in() {
        reset_failures(auth, opts, &rec).await?;
    }
    if body.disable_session == Some(true) {
        let token = match &ch {
            Challenge::Session(s) => Some(s.session.token.clone()),
            Challenge::SignIn { .. } => None,
        };
        return Ok(ApiResponse::ok(Verified { token, user: auth.public_user(ch.user().clone()) }));
    }
    complete(auth, opts, meta, ch, body.trust_device == Some(true)).await
}

/// `POST /two-factor/generate-backup-codes` `{ password }` → `{ status, backupCodes }`.
/// Replaces all existing codes.
pub async fn regenerate_backup_codes(auth: &Auth, opts: &TwoFactorOptions, meta: &RequestMeta, body: PasswordBody) -> Result<ApiResponse<Value>> {
    let current = require_session(auth, &meta.headers).await?;
    if !two_factor_enabled(&current.user) {
        return Err(bad("TWO_FACTOR_NOT_ENABLED"));
    }
    check_password(auth, opts, &current.user.id, body.password.as_deref()).await?;
    let rec = find_record(auth, &current.user.id).await?.ok_or_else(|| bad("TWO_FACTOR_NOT_ENABLED"))?;
    let codes = generate_backup_codes(opts);
    let mut d = Record::new();
    d.insert("backupCodes".into(), encrypt_codes(auth, &codes).into());
    update_record(auth, &rec.id, d).await?;
    Ok(ApiResponse::ok(json!({ "status": true, "backupCodes": codes })))
}

/// Server-side only: a user's remaining backup codes.
pub async fn view_backup_codes(auth: &Auth, user_id: &str) -> Result<Vec<String>> {
    let rec = find_record(auth, user_id).await?.ok_or_else(|| bad("BACKUP_CODES_NOT_ENABLED"))?;
    decrypt_codes(auth, &rec.backup_codes).ok_or_else(|| bad("INVALID_BACKUP_CODE"))
}

/// Server-side only: the current TOTP code for a user (e.g. for tests or support tooling).
pub async fn current_totp(auth: &Auth, opts: &TwoFactorOptions, user_id: &str) -> Result<String> {
    let rec = find_record(auth, user_id).await?.ok_or_else(|| bad("TOTP_NOT_ENABLED"))?;
    Ok(totp_now(&decrypt_secret(auth, &rec.secret)?, opts.totp.period, opts.totp.digits))
}

// ---- sign-in interception ----------------------------------------------------------------

impl TwoFactor {
    async fn intercept_sign_in(&self, auth: &Auth, req: &RequestInfo, res: Response) -> Response {
        if res.status() != StatusCode::OK {
            return res;
        }
        let (parts, body) = res.into_parts();
        let Ok(bytes) = axum::body::to_bytes(body, usize::MAX).await else {
            return AuthError::internal("failed to read response").into_response();
        };
        let rebuild = |parts, bytes| Response::from_parts(parts, Body::from(bytes));
        let Ok(json) = serde_json::from_slice::<Value>(&bytes) else { return rebuild(parts, bytes) };
        let user = &json["user"];
        if user["twoFactorEnabled"] != Value::Bool(true) {
            return rebuild(parts, bytes);
        }
        let (Some(user_id), Some(token)) = (user["id"].as_str(), json["token"].as_str()) else { return rebuild(parts, bytes) };
        match self.challenge_sign_in(auth, req, parts, user_id, token).await {
            Ok(Ok(res)) => res,
            Ok(Err(parts)) => rebuild(parts, bytes),
            Err(e) => e.into_response(),
        }
    }

    /// `Ok(Err(parts))` = device is trusted, keep the original response.
    async fn challenge_sign_in(
        &self,
        auth: &Auth,
        req: &RequestInfo,
        mut parts: axum::http::response::Parts,
        user_id: &str,
        token: &str,
    ) -> Result<std::result::Result<Response, axum::http::response::Parts>> {
        let opts = &self.opts;
        let trust_cookie = auth.cookies.name("trust_device");
        let (trusted, trust_identifier) = check_trusted_device(auth, &req.headers, user_id).await?;
        if trusted {
            // Rotate the trust token on every use.
            if let Some(old) = &trust_identifier {
                auth.db.delete_verifications_by_identifier(old).await?;
            }
            let cookie = trust_device_cookie(auth, opts, user_id).await?;
            if let Ok(v) = HeaderValue::from_str(&cookie) {
                parts.headers.append(SET_COOKIE, v);
            }
            return Ok(Err(parts));
        }

        // Undo the session the sign-in just created and issue a challenge instead.
        auth.db.delete_session(token).await?;
        let max_age = opts.two_factor_cookie_max_age;
        let identifier = format!("2fa-{}", random_string_from(20, URL_SAFE_ALPHABET));
        let expires = Utc::now() + Duration::seconds(max_age);
        auth.db.create_verification(&identifier, user_id, expires).await?;
        auth.db.create_verification(&format!("2fa-attempts-{identifier}"), "0", expires).await?;

        let mut methods = Vec::new();
        if !opts.totp.disable && find_record(auth, user_id).await?.is_some_and(|r| r.verified != Some(false)) {
            methods.push("totp");
        }
        if opts.otp.send_otp.is_some() {
            methods.push("otp");
        }

        let mut res = (StatusCode::OK, axum::Json(json!({ "twoFactorRedirect": true, "twoFactorMethods": methods }))).into_response();
        let headers = res.headers_mut();
        // Keep cookies other than the session token (e.g. dont_remember carries rememberMe).
        for c in parts.headers.get_all(SET_COOKIE) {
            let is_session = c.to_str().ok().and_then(|s| parse_set_cookie(s, &auth.cookies.session_token)).is_some();
            if !is_session {
                headers.append(SET_COOKIE, c.clone());
            }
        }
        let mut cookies = vec![
            auth.cookies.clear(&auth.cookies.session_token),
            auth.cookies.set_signed(&auth.cookies.name("two_factor"), &identifier, auth.secret(), Some(max_age)),
        ];
        if trust_identifier.is_some() {
            cookies.push(auth.cookies.clear(&trust_cookie));
        }
        for c in cookies {
            if let Ok(v) = HeaderValue::from_str(&c) {
                headers.append(SET_COOKIE, v);
            }
        }
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        Ok(Ok(res))
    }
}

// ---- plugin wiring -----------------------------------------------------------------------

macro_rules! route {
    ($f:path, $body:ty) => {
        post(|State(a): State<Auth>, m: RequestMeta, Extension(o): Extension<Opts>, JsonBody(b): JsonBody<$body>| async move {
            $f(&a, &o, &m, b).await
        })
    };
}

#[async_trait]
impl Plugin for TwoFactor {
    fn id(&self) -> &'static str {
        "two-factor"
    }

    fn schema(&self) -> Schema {
        Schema::new(vec![
            Table::new(USER, vec![Field::boolean("twoFactorEnabled").optional().default(false)]),
            Table::new(
                TABLE,
                vec![
                    Field::string("secret").hidden().index(),
                    Field::string("backupCodes").hidden(),
                    Field::string("userId").references(USER, "id").hidden(),
                    Field::boolean("verified").optional().default(true),
                    Field::integer("failedVerificationCount").optional().default(0).hidden(),
                    Field::date("lockedUntil").optional().hidden(),
                ],
            ),
        ])
    }

    fn rate_limit_rules(&self) -> Vec<RateLimitRule> {
        vec![RateLimitRule::new("/two-factor/", 10, 3)]
    }

    fn routes(&self) -> Option<Router<Auth>> {
        Some(
            Router::new()
                .route("/two-factor/enable", route!(enable, EnableBody))
                .route("/two-factor/disable", route!(disable, PasswordBody))
                .route("/two-factor/get-totp-uri", route!(get_totp_uri, PasswordBody))
                .route("/two-factor/verify-totp", route!(verify_totp_endpoint, VerifyBody))
                .route("/two-factor/verify-otp", route!(verify_otp, VerifyBody))
                .route("/two-factor/verify-backup-code", route!(verify_backup_code, VerifyBody))
                .route("/two-factor/generate-backup-codes", route!(regenerate_backup_codes, PasswordBody))
                .route(
                    "/two-factor/send-otp",
                    post(|State(a): State<Auth>, m: RequestMeta, Extension(o): Extension<Opts>| async move { send_otp(&a, &o, &m).await }),
                )
                .layer(Extension(self.opts.clone())),
        )
    }

    async fn on_response(&self, auth: &Auth, req: &RequestInfo, res: Response) -> Response {
        if SIGN_IN_PATHS.contains(&req.path.as_str()) {
            self.intercept_sign_in(auth, req, res).await
        } else {
            res
        }
    }
}

