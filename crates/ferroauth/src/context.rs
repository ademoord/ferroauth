//! The `Auth` instance and its builder.

use std::ops::Deref;
use std::sync::Arc;

use axum::http::HeaderMap;
use axum::{Extension, Router};
use url::Url;

use crate::cookies::CookieConfig;
use crate::crypto::{PasswordHasher, ScryptHasher};
use crate::db::{Adapter, DatabaseHooks, InternalAdapter, MemoryAdapter};
use crate::error::{AuthError, Result};
use crate::models::{SessionWithUser, User};
#[cfg(feature = "oauth")]
use crate::oauth::OAuthProvider;
use crate::options::AuthOptions;
use crate::plugins::Plugin;
use crate::rate_limit::RateLimiter;
use crate::schema::{Schema, USER};

pub struct AuthContext {
    pub options: AuthOptions,
    pub(crate) secret: String,
    pub schema: Schema,
    pub db: InternalAdapter,
    pub cookies: CookieConfig,
    pub hasher: Arc<dyn PasswordHasher>,
    pub plugins: Vec<Arc<dyn Plugin>>,
    #[cfg(feature = "oauth")]
    pub providers: Vec<Arc<dyn OAuthProvider>>,
    #[cfg(feature = "oauth")]
    pub http: reqwest::Client,
    pub(crate) rate_limiter: RateLimiter,
    trusted_origins: Vec<String>,
    adapter: Arc<dyn Adapter>,
}

/// A configured auth instance. Cheap to clone.
#[derive(Clone)]
pub struct Auth(Arc<AuthContext>);

impl Deref for Auth {
    type Target = AuthContext;
    fn deref(&self) -> &AuthContext {
        &self.0
    }
}

pub struct AuthBuilder {
    options: AuthOptions,
    adapter: Option<Arc<dyn Adapter>>,
    plugins: Vec<Arc<dyn Plugin>>,
    #[cfg(feature = "oauth")]
    providers: Vec<Arc<dyn OAuthProvider>>,
    hooks: Vec<Arc<dyn DatabaseHooks>>,
    hasher: Arc<dyn PasswordHasher>,
    migrate: bool,
}

impl AuthBuilder {
    /// Storage backend. Defaults to an in-memory adapter.
    pub fn database(mut self, adapter: impl Adapter) -> Self {
        self.adapter = Some(Arc::new(adapter));
        self
    }

    pub fn database_arc(mut self, adapter: Arc<dyn Adapter>) -> Self {
        self.adapter = Some(adapter);
        self
    }

    pub fn plugin(mut self, plugin: impl Plugin) -> Self {
        self.plugins.push(Arc::new(plugin));
        self
    }

    #[cfg(feature = "oauth")]
    pub fn social_provider(mut self, provider: impl OAuthProvider) -> Self {
        self.providers.push(Arc::new(provider));
        self
    }

    pub fn database_hooks(mut self, hooks: impl DatabaseHooks) -> Self {
        self.hooks.push(Arc::new(hooks));
        self
    }

    pub fn password_hasher(mut self, hasher: impl PasswordHasher) -> Self {
        self.hasher = Arc::new(hasher);
        self
    }

    /// Create missing tables / columns on startup. Default true.
    pub fn auto_migrate(mut self, migrate: bool) -> Self {
        self.migrate = migrate;
        self
    }

    pub async fn build(self) -> Result<Auth> {
        let mut options = self.options;
        options.base_url = options.base_url.trim_end_matches('/').to_string();
        options.base_path = format!("/{}", options.base_path.trim_matches('/'));
        if options.base_path == "/" {
            options.base_path.clear();
        }
        Url::parse(&options.base_url).map_err(|_| AuthError::internal(format!("invalid base_url: {}", options.base_url)))?;

        let secret = options
            .secret
            .clone()
            .or_else(|| std::env::var("FERROAUTH_SECRET").ok())
            .or_else(|| std::env::var("AUTH_SECRET").ok())
            .filter(|s| !s.is_empty());
        let secret = match secret {
            Some(s) => s,
            None if cfg!(debug_assertions) => {
                tracing::warn!("no auth secret configured; using an insecure development default");
                "ferroauth-insecure-development-secret-0000".to_string()
            }
            None => return Err(AuthError::internal("an auth secret is required (options.secret or FERROAUTH_SECRET)")),
        };
        if secret.len() < 32 {
            tracing::warn!("auth secret is shorter than 32 characters");
        }

        let mut schema = Schema::core();
        schema.merge(Schema::extend_table(USER, options.user.additional_fields.clone()));
        let mut hooks = self.hooks;
        for p in &self.plugins {
            schema.merge(p.schema());
            if let Some(h) = p.database_hooks() {
                hooks.push(h);
            }
        }

        let adapter = self.adapter.unwrap_or_else(|| Arc::new(MemoryAdapter::new()));
        adapter.init(&schema, self.migrate).await?;

        let secure = options.advanced.use_secure_cookies.unwrap_or_else(|| options.base_url.starts_with("https://"));
        let cookies = CookieConfig::new(&options.advanced.cookie_prefix, secure, options.advanced.cross_subdomain_cookie_domain.clone());

        let mut trusted_origins = vec![options.base_url.clone()];
        trusted_origins.extend(options.trusted_origins.iter().map(|o| o.trim_end_matches('/').to_string()));

        let mut rules = options.rate_limit.custom_rules.clone();
        for p in &self.plugins {
            rules.extend(p.rate_limit_rules());
        }
        let rate_limiter = RateLimiter::new(options.rate_limit.window, options.rate_limit.max, rules);

        let ctx = AuthContext {
            secret,
            db: InternalAdapter::new(adapter.clone(), hooks, schema.clone()),
            schema,
            cookies,
            hasher: self.hasher,
            plugins: self.plugins,
            #[cfg(feature = "oauth")]
            providers: self.providers,
            #[cfg(feature = "oauth")]
            http: reqwest::Client::builder()
                .user_agent(concat!("ferroauth/", env!("CARGO_PKG_VERSION")))
                .build()
                .map_err(|e| AuthError::internal(e.to_string()))?,
            rate_limiter,
            trusted_origins,
            adapter,
            options,
        };
        Ok(Auth(Arc::new(ctx)))
    }
}

impl Auth {
    pub fn builder(options: AuthOptions) -> AuthBuilder {
        AuthBuilder {
            options,
            adapter: None,
            plugins: Vec::new(),
            #[cfg(feature = "oauth")]
            providers: Vec::new(),
            hooks: Vec::new(),
            hasher: Arc::new(ScryptHasher),
            migrate: true,
        }
    }

    /// The auth router, already mounted under `base_path`. Merge it into your app:
    /// `app.merge(auth.router())`.
    pub fn router(&self) -> Router {
        crate::routes::build_router(self.clone())
    }

    /// Layer that makes [`crate::AuthSession`] extractors work in your own routes.
    pub fn layer(&self) -> Extension<Auth> {
        Extension(self.clone())
    }

    /// Look up the session for a request's headers (cookie or plugin-provided token).
    /// Does not refresh the session.
    pub async fn get_session(&self, headers: &HeaderMap) -> Result<Option<SessionWithUser>> {
        Ok(crate::session::get_session(self, headers, false).await?.data)
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }

    pub fn raw_adapter(&self) -> &dyn Adapter {
        self.adapter.as_ref()
    }

    /// `base_url + base_path`, e.g. `http://localhost:3000/api/auth`.
    pub fn api_url(&self) -> String {
        format!("{}{}", self.options.base_url, self.options.base_path)
    }

    /// SQL DDL for the full schema, if the adapter is SQL based.
    pub fn generate_schema_sql(&self) -> Option<String> {
        self.adapter.generate_schema_sql(&self.schema)
    }

    #[cfg(feature = "oauth")]
    pub fn provider(&self, id: &str) -> Option<Arc<dyn OAuthProvider>> {
        self.providers.iter().find(|p| p.id() == id).cloned()
    }

    pub fn is_trusted_origin(&self, url: &str) -> bool {
        let Ok(parsed) = Url::parse(url) else { return false };
        let origin = parsed.origin().ascii_serialization();
        self.trusted_origins.iter().any(|pattern| origin_matches(pattern, &origin))
    }

    /// Reject open redirects: relative paths and trusted origins are allowed.
    pub fn validate_redirect(&self, url: Option<&str>) -> Result<()> {
        match url {
            None => Ok(()),
            Some(u) if is_safe_relative(u) => Ok(()),
            Some(u) if self.is_trusted_origin(u) => Ok(()),
            Some(_) => Err(AuthError::invalid_callback_url()),
        }
    }

    /// Strip fields marked hidden in the schema from a user before returning it.
    pub fn public_user(&self, mut user: User) -> User {
        if let Some(table) = self.schema.table(USER) {
            user.extra.retain(|k, _| table.field(k).is_none_or(|f| f.returned));
        }
        user
    }

    pub async fn hash_password(&self, password: &str) -> String {
        let hasher = self.hasher.clone();
        let password = password.to_string();
        tokio::task::spawn_blocking(move || hasher.hash(&password)).await.expect("password hashing panicked")
    }

    pub async fn verify_password(&self, hash: &str, password: &str) -> bool {
        let hasher = self.hasher.clone();
        let (hash, password) = (hash.to_string(), password.to_string());
        tokio::task::spawn_blocking(move || hasher.verify(&hash, &password)).await.unwrap_or(false)
    }

    pub(crate) fn check_password_length(&self, password: &str) -> Result<()> {
        let o = &self.options.email_and_password;
        let len = password.chars().count();
        if len < o.min_password_length {
            return Err(AuthError::password_too_short());
        }
        if len > o.max_password_length {
            return Err(AuthError::password_too_long());
        }
        Ok(())
    }
}

fn is_safe_relative(u: &str) -> bool {
    u.starts_with('/') && !u.starts_with("//") && !u.contains('\\') && !u.contains("/\t") && !u.chars().any(|c| c.is_control())
}

fn origin_matches(pattern: &str, origin: &str) -> bool {
    if let Some(idx) = pattern.find("://*.") {
        let scheme = &pattern[..idx];
        let suffix = &pattern[idx + 4..]; // ".example.com"
        return origin.starts_with(&format!("{scheme}://")) && origin.ends_with(suffix);
    }
    match Url::parse(pattern) {
        Ok(u) => u.origin().ascii_serialization() == origin,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_patterns() {
        assert!(origin_matches("https://example.com", "https://example.com"));
        assert!(origin_matches("https://example.com/", "https://example.com"));
        assert!(!origin_matches("https://example.com", "https://evil.com"));
        assert!(origin_matches("https://*.example.com", "https://app.example.com"));
        assert!(!origin_matches("https://*.example.com", "https://example.com.evil.com"));
        assert!(!origin_matches("https://*.example.com", "http://app.example.com"));
        assert!(is_safe_relative("/dashboard?x=1"));
        assert!(!is_safe_relative("//evil.com"));
        assert!(!is_safe_relative("/\\evil.com"));
    }
}
