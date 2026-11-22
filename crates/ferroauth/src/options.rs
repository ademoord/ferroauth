//! Configuration.
//! All structs implement `Default`; use struct-update syntax:
//!
//! ```ignore
//! AuthOptions {
//!     base_url: "http://localhost:3000".into(),
//!     email_and_password: EmailAndPasswordOptions { enabled: true, ..Default::default() },
//!     ..Default::default()
//! }
//! ```

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::models::User;
use crate::schema::Field;

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// An async callback (used for sending emails).
pub struct Callback<T>(Arc<dyn Fn(T) -> BoxFuture<()> + Send + Sync>);

impl<T> Clone for Callback<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> fmt::Debug for Callback<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Callback")
    }
}

impl<T: 'static> Callback<T> {
    pub fn new<F, Fut>(f: F) -> Self
    where
        F: Fn(T) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        Self(Arc::new(move |t| Box::pin(f(t))))
    }

    pub async fn call(&self, value: T) {
        (self.0)(value).await
    }
}

/// Payload for `email_verification.send_verification_email`.
#[derive(Debug, Clone)]
pub struct VerificationEmail {
    pub user: User,
    pub url: String,
    pub token: String,
}

/// Payload for `email_and_password.send_reset_password`.
#[derive(Debug, Clone)]
pub struct ResetPasswordEmail {
    pub user: User,
    pub url: String,
    pub token: String,
}

/// Payload for `user.change_email.send_change_email_verification` (sent to the *current* address).
#[derive(Debug, Clone)]
pub struct ChangeEmailVerification {
    pub user: User,
    pub new_email: String,
    pub url: String,
    pub token: String,
}

#[derive(Debug, Clone)]
pub struct AuthOptions {
    pub app_name: String,
    /// Public origin of the server, e.g. `https://example.com`. Used for
    /// callback URLs and as a trusted origin.
    pub base_url: String,
    /// Where the auth router is mounted. Default `/api/auth`.
    pub base_path: String,
    /// Secret for signing cookies and tokens. Falls back to the
    /// `FERROAUTH_SECRET` / `AUTH_SECRET` env vars.
    pub secret: Option<String>,
    /// Extra origins allowed to call the API and to be used as redirect targets.
    /// Supports a leading wildcard host: `https://*.example.com`.
    pub trusted_origins: Vec<String>,
    pub session: SessionOptions,
    pub email_and_password: EmailAndPasswordOptions,
    pub email_verification: EmailVerificationOptions,
    pub account: AccountOptions,
    pub user: UserOptions,
    pub rate_limit: RateLimitOptions,
    pub advanced: AdvancedOptions,
}

impl Default for AuthOptions {
    fn default() -> Self {
        Self {
            app_name: "ferroauth".into(),
            base_url: "http://localhost:3000".into(),
            base_path: "/api/auth".into(),
            secret: None,
            trusted_origins: Vec::new(),
            session: SessionOptions::default(),
            email_and_password: EmailAndPasswordOptions::default(),
            email_verification: EmailVerificationOptions::default(),
            account: AccountOptions::default(),
            user: UserOptions::default(),
            rate_limit: RateLimitOptions::default(),
            advanced: AdvancedOptions::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SessionOptions {
    /// Session lifetime in seconds. Default 7 days.
    pub expires_in: i64,
    /// How often (seconds) the expiry is pushed forward on use. Default 1 day.
    pub update_age: i64,
    /// A session younger than this (seconds) is "fresh" — required for
    /// sensitive operations like deleting the account. Default 1 day.
    pub fresh_age: i64,
    pub disable_session_refresh: bool,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self { expires_in: 60 * 60 * 24 * 7, update_age: 60 * 60 * 24, fresh_age: 60 * 60 * 24, disable_session_refresh: false }
    }
}

#[derive(Debug, Clone)]
pub struct EmailAndPasswordOptions {
    pub enabled: bool,
    pub disable_sign_up: bool,
    pub require_email_verification: bool,
    pub min_password_length: usize,
    pub max_password_length: usize,
    /// Sign the user in right after sign-up. Default true.
    pub auto_sign_in: bool,
    pub send_reset_password: Option<Callback<ResetPasswordEmail>>,
    /// Seconds. Default 1 hour.
    pub reset_password_token_expires_in: i64,
    pub revoke_sessions_on_password_reset: bool,
}

impl Default for EmailAndPasswordOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            disable_sign_up: false,
            require_email_verification: false,
            min_password_length: 8,
            max_password_length: 128,
            auto_sign_in: true,
            send_reset_password: None,
            reset_password_token_expires_in: 3600,
            revoke_sessions_on_password_reset: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EmailVerificationOptions {
    pub send_verification_email: Option<Callback<VerificationEmail>>,
    pub send_on_sign_up: bool,
    /// Resend the verification email when an unverified user tries to sign in
    /// (only when `require_email_verification` is on).
    pub send_on_sign_in: bool,
    pub auto_sign_in_after_verification: bool,
    /// Seconds. Default 1 hour.
    pub expires_in: i64,
}

impl Default for EmailVerificationOptions {
    fn default() -> Self {
        Self {
            send_verification_email: None,
            send_on_sign_up: false,
            send_on_sign_in: false,
            auto_sign_in_after_verification: false,
            expires_in: 3600,
        }
    }
}

#[derive(Debug, Clone)]
#[derive(Default)]
pub struct AccountOptions {
    pub account_linking: AccountLinkingOptions,
}


#[derive(Debug, Clone)]
pub struct AccountLinkingOptions {
    pub enabled: bool,
    /// Providers whose accounts are linked to an existing user with the same
    /// email even if the provider does not report the email as verified.
    pub trusted_providers: Vec<String>,
    /// Allow `link-social` to link an account whose email differs from the user's.
    pub allow_different_emails: bool,
}

impl Default for AccountLinkingOptions {
    fn default() -> Self {
        Self { enabled: true, trusted_providers: Vec::new(), allow_different_emails: false }
    }
}

#[derive(Debug, Clone, Default)]
pub struct UserOptions {
    /// Extra columns on the user table.
    /// Mark with `.input()` to accept them on sign-up / update-user.
    pub additional_fields: Vec<Field>,
    pub change_email: ChangeEmailOptions,
    pub delete_user: DeleteUserOptions,
}

#[derive(Debug, Clone, Default)]
pub struct ChangeEmailOptions {
    pub enabled: bool,
    /// Confirmation sent to the *current* address when it is verified.
    pub send_change_email_verification: Option<Callback<ChangeEmailVerification>>,
}

#[derive(Debug, Clone, Default)]
pub struct DeleteUserOptions {
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct RateLimitRule {
    /// Path prefix relative to the base path, e.g. `/sign-in`.
    pub path_prefix: String,
    /// Seconds.
    pub window: u64,
    pub max: u32,
}

impl RateLimitRule {
    pub fn new(path_prefix: impl Into<String>, window: u64, max: u32) -> Self {
        Self { path_prefix: path_prefix.into(), window, max }
    }
}

#[derive(Debug, Clone)]
pub struct RateLimitOptions {
    pub enabled: bool,
    /// Seconds. Default 10.
    pub window: u64,
    /// Requests per window per IP. Default 100.
    pub max: u32,
    /// Overrides; the default includes stricter limits for sign-in / sign-up etc.
    pub custom_rules: Vec<RateLimitRule>,
}

impl Default for RateLimitOptions {
    fn default() -> Self {
        let strict = ["/sign-in", "/sign-up", "/change-password", "/change-email", "/request-password-reset", "/forget-password", "/send-verification-email"];
        Self {
            enabled: true,
            window: 10,
            max: 100,
            custom_rules: strict.iter().map(|p| RateLimitRule::new(*p, 10, 3)).collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AdvancedOptions {
    /// Cookie name prefix. Default `ferroauth`.
    pub cookie_prefix: String,
    /// Force `Secure` cookies on/off. Default: on when `base_url` is https.
    pub use_secure_cookies: Option<bool>,
    /// Share cookies across subdomains of this domain, e.g. `example.com`.
    pub cross_subdomain_cookie_domain: Option<String>,
    pub disable_csrf_check: bool,
    /// Headers checked (in order) for the client IP. Default `x-forwarded-for`.
    pub ip_address_headers: Vec<String>,
    /// Don't record IP addresses on sessions. Default false.
    pub disable_ip_tracking: bool,
}

impl Default for AdvancedOptions {
    fn default() -> Self {
        Self {
            cookie_prefix: "ferroauth".into(),
            use_secure_cookies: None,
            cross_subdomain_cookie_domain: None,
            disable_csrf_check: false,
            ip_address_headers: vec!["x-forwarded-for".into()],
            disable_ip_tracking: false,
        }
    }
}
