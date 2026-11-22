//! OAuth 2.0 / OIDC social sign-in. [`OAuth2Provider`] is a configurable
//! generic provider; [`providers`] has presets (GitHub, Google, Discord).
//! Implement [`OAuthProvider`] directly for anything exotic.

pub mod providers;

use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Duration, Utc};
use reqwest::header::{ACCEPT, AUTHORIZATION};
use serde_json::Value;
use url::Url;

use crate::crypto::pkce_challenge;
use crate::error::{AuthError, Result};
use crate::models::Timestamp;
use crate::options::BoxFuture;

#[derive(Debug, Clone, Default)]
pub struct OAuthTokens {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub token_type: Option<String>,
    pub access_token_expires_at: Option<Timestamp>,
    pub refresh_token_expires_at: Option<Timestamp>,
    pub scopes: Vec<String>,
    /// The raw token response.
    pub raw: Value,
}

impl OAuthTokens {
    pub fn from_response(v: Value) -> Self {
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        let secs = |k: &str| v.get(k).and_then(|x| x.as_i64().or_else(|| x.as_str().and_then(|s| s.parse().ok())));
        Self {
            access_token: s("access_token"),
            refresh_token: s("refresh_token"),
            id_token: s("id_token"),
            token_type: s("token_type"),
            access_token_expires_at: secs("expires_in").map(|n| Utc::now() + Duration::seconds(n)),
            refresh_token_expires_at: secs("refresh_token_expires_in").map(|n| Utc::now() + Duration::seconds(n)),
            scopes: s("scope").map(|s| s.split([' ', ',']).filter(|x| !x.is_empty()).map(String::from).collect()).unwrap_or_default(),
            raw: v,
        }
    }
}

/// Normalised profile returned by a provider.
#[derive(Debug, Clone)]
pub struct OAuthUserInfo {
    /// Stable provider-side account id.
    pub id: String,
    pub name: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub image: Option<String>,
}

pub struct AuthorizationRequest<'a> {
    pub state: &'a str,
    pub code_verifier: &'a str,
    pub redirect_uri: &'a str,
    /// Extra scopes requested by the client in addition to the provider defaults.
    pub scopes: &'a [String],
}

#[async_trait]
pub trait OAuthProvider: Send + Sync + 'static {
    fn id(&self) -> &str;
    fn authorization_url(&self, req: AuthorizationRequest<'_>) -> Result<String>;
    async fn exchange_code(&self, http: &reqwest::Client, code: &str, code_verifier: &str, redirect_uri: &str) -> Result<OAuthTokens>;
    async fn user_info(&self, http: &reqwest::Client, tokens: &OAuthTokens) -> Result<OAuthUserInfo>;
    /// Prevent creating new users through this provider (existing users can still sign in).
    fn disable_sign_up(&self) -> bool {
        false
    }
}

pub type ProfileMapper = Arc<dyn Fn(&Value) -> Option<OAuthUserInfo> + Send + Sync>;
pub type ProfileFetcher = Arc<dyn Fn(reqwest::Client, OAuthTokens) -> BoxFuture<Result<Value>> + Send + Sync>;

#[derive(Clone)]
pub enum ProfileSource {
    /// GET this URL with the access token as a bearer token.
    UserInfoEndpoint(String),
    /// Read the claims of the `id_token` from the token response (received
    /// directly from the token endpoint over TLS, per OIDC Core 3.1.3.7).
    IdToken,
    Custom(ProfileFetcher),
}

/// A generic, configurable OAuth 2.0 provider.
#[derive(Clone)]
pub struct OAuth2Provider {
    pub id: String,
    pub client_id: String,
    pub client_secret: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub profile: ProfileSource,
    pub map_profile: ProfileMapper,
    pub scopes: Vec<String>,
    pub pkce: bool,
    pub authorization_params: Vec<(String, String)>,
    pub disable_sign_up: bool,
}

impl OAuth2Provider {
    pub fn new(
        id: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        authorization_endpoint: impl Into<String>,
        token_endpoint: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            authorization_endpoint: authorization_endpoint.into(),
            token_endpoint: token_endpoint.into(),
            profile: ProfileSource::IdToken,
            map_profile: Arc::new(oidc_profile),
            scopes: vec!["openid".into(), "email".into(), "profile".into()],
            pkce: true,
            authorization_params: Vec::new(),
            disable_sign_up: false,
        }
    }

    pub fn userinfo_endpoint(mut self, url: impl Into<String>) -> Self {
        self.profile = ProfileSource::UserInfoEndpoint(url.into());
        self
    }

    pub fn scopes(mut self, scopes: &[&str]) -> Self {
        self.scopes = scopes.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn pkce(mut self, enabled: bool) -> Self {
        self.pkce = enabled;
        self
    }

    pub fn param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.authorization_params.push((key.into(), value.into()));
        self
    }

    pub fn map_profile(mut self, f: impl Fn(&Value) -> Option<OAuthUserInfo> + Send + Sync + 'static) -> Self {
        self.map_profile = Arc::new(f);
        self
    }

    pub fn disable_sign_up(mut self, disabled: bool) -> Self {
        self.disable_sign_up = disabled;
        self
    }
}

/// Standard OIDC claims → profile.
pub fn oidc_profile(v: &Value) -> Option<OAuthUserInfo> {
    let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    let id = s("sub").or_else(|| v.get("id").map(|x| x.as_str().map(str::to_string).unwrap_or_else(|| x.to_string())))?;
    let email = s("email");
    Some(OAuthUserInfo {
        name: s("name").or_else(|| s("preferred_username")).or_else(|| email.clone()).unwrap_or_default(),
        email_verified: v.get("email_verified").and_then(|x| x.as_bool().or_else(|| x.as_str().map(|s| s == "true"))).unwrap_or(false),
        image: s("picture"),
        email,
        id,
    })
}

/// Decode (without verifying) the payload of a JWT.
pub fn decode_jwt_payload(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?).ok()
}

pub(crate) async fn get_json(http: &reqwest::Client, url: &str, access_token: &str) -> Result<Value> {
    let res = http
        .get(url)
        .header(AUTHORIZATION, format!("Bearer {access_token}"))
        .header(ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| AuthError::internal(format!("userinfo request failed: {e}")))?;
    if !res.status().is_success() {
        tracing::warn!(status = %res.status(), url, "userinfo request failed");
        return Err(AuthError::failed_to_get_user_info());
    }
    res.json().await.map_err(|_| AuthError::failed_to_get_user_info())
}

#[async_trait]
impl OAuthProvider for OAuth2Provider {
    fn id(&self) -> &str {
        &self.id
    }

    fn authorization_url(&self, req: AuthorizationRequest<'_>) -> Result<String> {
        let mut url = Url::parse(&self.authorization_endpoint).map_err(|_| AuthError::internal("invalid authorization endpoint"))?;
        let mut scopes = self.scopes.clone();
        for s in req.scopes {
            if !scopes.contains(s) {
                scopes.push(s.clone());
            }
        }
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("response_type", "code")
                .append_pair("client_id", &self.client_id)
                .append_pair("redirect_uri", req.redirect_uri)
                .append_pair("state", req.state);
            if !scopes.is_empty() {
                q.append_pair("scope", &scopes.join(" "));
            }
            if self.pkce {
                q.append_pair("code_challenge", &pkce_challenge(req.code_verifier)).append_pair("code_challenge_method", "S256");
            }
            for (k, v) in &self.authorization_params {
                q.append_pair(k, v);
            }
        }
        Ok(url.to_string())
    }

    async fn exchange_code(&self, http: &reqwest::Client, code: &str, code_verifier: &str, redirect_uri: &str) -> Result<OAuthTokens> {
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
        ];
        if self.pkce {
            form.push(("code_verifier", code_verifier));
        }
        let body = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(form).finish();
        let res = http
            .post(&self.token_endpoint)
            .header(ACCEPT, "application/json")
            .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .map_err(|e| AuthError::internal(format!("token request failed: {e}")))?;
        let status = res.status();
        let v: Value = res.json().await.map_err(|_| AuthError::invalid_token())?;
        if !status.is_success() || v.get("error").is_some() {
            tracing::warn!(provider = %self.id, %status, response = %v, "code exchange failed");
            return Err(AuthError::invalid_token());
        }
        Ok(OAuthTokens::from_response(v))
    }

    async fn user_info(&self, http: &reqwest::Client, tokens: &OAuthTokens) -> Result<OAuthUserInfo> {
        let profile = match &self.profile {
            ProfileSource::UserInfoEndpoint(url) => {
                let at = tokens.access_token.as_deref().ok_or_else(AuthError::failed_to_get_user_info)?;
                get_json(http, url, at).await?
            }
            ProfileSource::IdToken => {
                let idt = tokens.id_token.as_deref().ok_or_else(AuthError::failed_to_get_user_info)?;
                decode_jwt_payload(idt).ok_or_else(AuthError::failed_to_get_user_info)?
            }
            ProfileSource::Custom(f) => f(http.clone(), tokens.clone()).await?,
        };
        (self.map_profile)(&profile).ok_or_else(AuthError::failed_to_get_user_info)
    }

    fn disable_sign_up(&self) -> bool {
        self.disable_sign_up
    }
}
