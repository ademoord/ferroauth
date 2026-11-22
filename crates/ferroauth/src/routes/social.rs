//! Social sign-in: `POST /sign-in/social`, `POST /link-social`,
//! `GET|POST /callback/{provider}`.

use axum::extract::{Form, Path, Query, State};
use axum::response::{IntoResponse, Response};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::with_query;
use crate::context::Auth;
use crate::cookies::get_signed_cookie;
use crate::crypto::random_string;
use crate::db::Record;
use crate::error::{AuthError, Result};
use crate::models::{ts_value, User};
use crate::oauth::{AuthorizationRequest, OAuthProvider, OAuthTokens, OAuthUserInfo};
use crate::session::{create_session, require_session, ApiResponse, RequestMeta};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInSocial {
    pub provider: String,
    #[serde(default, rename = "callbackURL")]
    pub callback_url: Option<String>,
    #[serde(default, rename = "errorCallbackURL")]
    pub error_callback_url: Option<String>,
    #[serde(default, rename = "newUserCallbackURL")]
    pub new_user_callback_url: Option<String>,
    #[serde(default)]
    pub disable_redirect: Option<bool>,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkSocial {
    pub provider: String,
    #[serde(default, rename = "callbackURL")]
    pub callback_url: Option<String>,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct SocialRedirect {
    pub url: String,
    pub redirect: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LinkData {
    user_id: String,
    email: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StateData {
    callback_url: String,
    code_verifier: String,
    error_url: Option<String>,
    new_user_url: Option<String>,
    link: Option<LinkData>,
}

const STATE_TTL_SECS: i64 = 600;

fn redirect_uri(auth: &Auth, provider: &str) -> String {
    format!("{}/callback/{provider}", auth.api_url())
}

async fn start_flow(auth: &Auth, provider: &dyn OAuthProvider, data: StateData, scopes: &[String]) -> Result<(String, String)> {
    let state = random_string(32);
    let value = serde_json::to_string(&data).map_err(|e| AuthError::internal(e.to_string()))?;
    auth.db.create_verification(&state, &value, Utc::now() + Duration::seconds(STATE_TTL_SECS)).await?;
    let url = provider.authorization_url(AuthorizationRequest {
        state: &state,
        code_verifier: &data.code_verifier,
        redirect_uri: &redirect_uri(auth, provider.id()),
        scopes,
    })?;
    let cookie = auth.cookies.set_signed(&auth.cookies.state, &state, auth.secret(), Some(STATE_TTL_SECS));
    Ok((url, cookie))
}

pub async fn sign_in_social(auth: &Auth, _meta: &RequestMeta, body: SignInSocial) -> Result<ApiResponse<SocialRedirect>> {
    let provider = auth.provider(&body.provider).ok_or_else(AuthError::provider_not_found)?;
    for u in [&body.callback_url, &body.error_callback_url, &body.new_user_callback_url] {
        auth.validate_redirect(u.as_deref())?;
    }
    let data = StateData {
        callback_url: body.callback_url.unwrap_or_else(|| "/".into()),
        code_verifier: random_string(64),
        error_url: body.error_callback_url,
        new_user_url: body.new_user_callback_url,
        link: None,
    };
    let (url, cookie) = start_flow(auth, provider.as_ref(), data, body.scopes.as_deref().unwrap_or_default()).await?;
    Ok(ApiResponse::ok(SocialRedirect { url, redirect: body.disable_redirect != Some(true) }).with_cookies([cookie]))
}

pub async fn link_social(auth: &Auth, meta: &RequestMeta, body: LinkSocial) -> Result<ApiResponse<SocialRedirect>> {
    let current = require_session(auth, &meta.headers).await?;
    let provider = auth.provider(&body.provider).ok_or_else(AuthError::provider_not_found)?;
    auth.validate_redirect(body.callback_url.as_deref())?;
    let data = StateData {
        callback_url: body.callback_url.unwrap_or_else(|| "/".into()),
        code_verifier: random_string(64),
        error_url: None,
        new_user_url: None,
        link: Some(LinkData { user_id: current.user.id, email: current.user.email }),
    };
    let (url, cookie) = start_flow(auth, provider.as_ref(), data, body.scopes.as_deref().unwrap_or_default()).await?;
    Ok(ApiResponse::ok(SocialRedirect { url, redirect: true }).with_cookies([cookie]))
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct CallbackParams {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_description: Option<String>,
}

pub async fn callback_get(State(auth): State<Auth>, meta: RequestMeta, Path(provider): Path<String>, Query(q): Query<CallbackParams>) -> Response {
    handle_callback(&auth, &meta, &provider, q).await
}

/// `response_mode=form_post` (e.g. Apple): the cross-site POST carries no
/// SameSite=Lax cookies, so bounce to the GET handler as a top-level navigation.
pub async fn callback_post(State(auth): State<Auth>, Path(provider): Path<String>, Form(q): Form<CallbackParams>) -> Response {
    let qs = serde_urlencoded_like(&q);
    ApiResponse::redirect_to(format!("{}?{qs}", redirect_uri(&auth, &provider))).into_response()
}

fn serde_urlencoded_like(q: &CallbackParams) -> String {
    let mut s = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in [("code", &q.code), ("state", &q.state), ("error", &q.error), ("error_description", &q.error_description)] {
        if let Some(v) = v {
            s.append_pair(k, v);
        }
    }
    s.finish()
}

async fn handle_callback(auth: &Auth, meta: &RequestMeta, provider_id: &str, q: CallbackParams) -> Response {
    let default_error_url = format!("{}/error", auth.api_url());
    let fail = |url: Option<&str>, code: &str| -> Response {
        tracing::debug!(code, "oauth callback failed");
        let res = ApiResponse::redirect_to(with_query(url.unwrap_or(&default_error_url), "error", code));
        res.with_cookies([auth.cookies.clear(&auth.cookies.state)]).into_response()
    };

    let Some(state) = q.state.as_deref() else { return fail(None, "state_not_found") };
    let verification = match auth.db.find_verification(state).await {
        Ok(Some(v)) => v,
        _ => return fail(None, "please_restart_the_process"),
    };
    let _ = auth.db.delete_verification(&verification.id).await;
    let Ok(data) = serde_json::from_str::<StateData>(&verification.value) else { return fail(None, "invalid_state") };
    let error_url = data.error_url.clone().or_else(|| Some(data.callback_url.clone()));
    let error_url = error_url.as_deref();
    if verification.expires_at <= Utc::now() {
        return fail(error_url, "state_expired");
    }
    if get_signed_cookie(&meta.headers, &auth.cookies.state, auth.secret()).as_deref() != Some(state) {
        return fail(error_url, "state_mismatch");
    }
    if let Some(err) = &q.error {
        return fail(error_url, err);
    }
    let Some(code) = q.code.as_deref() else { return fail(error_url, "no_code") };
    let Some(provider) = auth.provider(provider_id) else { return fail(error_url, "provider_not_found") };

    let tokens = match provider.exchange_code(&auth.http, code, &data.code_verifier, &redirect_uri(auth, provider_id)).await {
        Ok(t) => t,
        Err(_) => return fail(error_url, "invalid_code"),
    };
    let info = match provider.user_info(&auth.http, &tokens).await {
        Ok(i) => i,
        Err(_) => return fail(error_url, "unable_to_get_user_info"),
    };
    let Some(email) = info.email.as_ref().map(|e| e.trim().to_lowercase()) else { return fail(error_url, "email_not_found") };
    let info = OAuthUserInfo { email: Some(email), ..info };

    let clear_state = auth.cookies.clear(&auth.cookies.state);
    if let Some(link) = &data.link {
        return match link_account(auth, provider_id, &info, &tokens, link).await {
            Ok(()) => ApiResponse::redirect_to(data.callback_url.clone()).with_cookies([clear_state]).into_response(),
            Err(code) => fail(error_url, code),
        };
    }

    let (user, is_new) = match find_or_create_user(auth, provider.as_ref(), &info, &tokens).await {
        Ok(r) => r,
        Err(code) => return fail(error_url, code),
    };
    let (_, cookies) = match create_session(auth, &user, meta, false).await {
        Ok(s) => s,
        Err(_) => return fail(error_url, "unable_to_create_session"),
    };
    let target = match (is_new, &data.new_user_url) {
        (true, Some(u)) => u.clone(),
        _ => data.callback_url.clone(),
    };
    ApiResponse::redirect_to(target).with_cookies(cookies).with_cookies([clear_state]).into_response()
}

fn token_fields(tokens: &OAuthTokens) -> Record {
    let mut r = Record::new();
    let opt = |s: &Option<String>| s.clone().map(Value::String).unwrap_or(Value::Null);
    r.insert("accessToken".into(), opt(&tokens.access_token));
    r.insert("idToken".into(), opt(&tokens.id_token));
    if tokens.refresh_token.is_some() {
        r.insert("refreshToken".into(), opt(&tokens.refresh_token));
    }
    r.insert("accessTokenExpiresAt".into(), tokens.access_token_expires_at.as_ref().map(ts_value).unwrap_or(Value::Null));
    if let Some(t) = &tokens.refresh_token_expires_at {
        r.insert("refreshTokenExpiresAt".into(), ts_value(t));
    }
    if !tokens.scopes.is_empty() {
        r.insert("scope".into(), tokens.scopes.join(",").into());
    }
    r
}

async fn create_oauth_account(auth: &Auth, user_id: &str, provider_id: &str, info: &OAuthUserInfo, tokens: &OAuthTokens) -> Result<()> {
    let mut data = token_fields(tokens);
    data.insert("accountId".into(), info.id.clone().into());
    data.insert("providerId".into(), provider_id.into());
    data.insert("userId".into(), user_id.into());
    auth.db.create_account(data).await?;
    Ok(())
}

async fn find_or_create_user(
    auth: &Auth,
    provider: &dyn OAuthProvider,
    info: &OAuthUserInfo,
    tokens: &OAuthTokens,
) -> std::result::Result<(User, bool), &'static str> {
    let email = info.email.clone().unwrap_or_default();
    let internal = |_| "internal_error";

    if let Some(account) = auth.db.find_account(&info.id, provider.id()).await.map_err(internal)? {
        let user = auth.db.find_user_by_id(&account.user_id).await.map_err(internal)?.ok_or("user_not_found")?;
        auth.db.update_account(&account.id, token_fields(tokens)).await.map_err(internal)?;
        if info.email_verified && !user.email_verified && user.email == email {
            let mut d = Record::new();
            d.insert("emailVerified".into(), true.into());
            return Ok((auth.db.update_user(&user.id, d).await.map_err(internal)?, false));
        }
        return Ok((user, false));
    }

    if let Some(user) = auth.db.find_user_by_email(&email).await.map_err(internal)? {
        let linking = &auth.options.account.account_linking;
        let trusted = linking.trusted_providers.iter().any(|p| p == provider.id());
        if !linking.enabled || (!trusted && !info.email_verified) {
            return Err("account_not_linked");
        }
        create_oauth_account(auth, &user.id, provider.id(), info, tokens).await.map_err(internal)?;
        if info.email_verified && !user.email_verified {
            let mut d = Record::new();
            d.insert("emailVerified".into(), true.into());
            return Ok((auth.db.update_user(&user.id, d).await.map_err(internal)?, false));
        }
        return Ok((user, false));
    }

    if provider.disable_sign_up() {
        return Err("signup_disabled");
    }
    let mut data = Record::new();
    data.insert("name".into(), info.name.clone().into());
    data.insert("email".into(), email.into());
    data.insert("emailVerified".into(), info.email_verified.into());
    data.insert("image".into(), info.image.clone().map(Value::String).unwrap_or(Value::Null));
    let user = auth.db.create_user(data).await.map_err(|_| "unable_to_create_user")?;
    create_oauth_account(auth, &user.id, provider.id(), info, tokens).await.map_err(internal)?;
    Ok((user, true))
}

async fn link_account(
    auth: &Auth,
    provider_id: &str,
    info: &OAuthUserInfo,
    tokens: &OAuthTokens,
    link: &LinkData,
) -> std::result::Result<(), &'static str> {
    let internal = |_| "internal_error";
    let email = info.email.clone().unwrap_or_default();
    if !auth.options.account.account_linking.allow_different_emails && email != link.email {
        return Err("email_doesn't_match");
    }
    match auth.db.find_account(&info.id, provider_id).await.map_err(internal)? {
        Some(existing) if existing.user_id != link.user_id => Err("account_already_linked_to_different_user"),
        Some(existing) => {
            auth.db.update_account(&existing.id, token_fields(tokens)).await.map_err(internal)?;
            Ok(())
        }
        None => create_oauth_account(auth, &link.user_id, provider_id, info, tokens).await.map_err(internal),
    }
}
