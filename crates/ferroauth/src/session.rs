//! Session resolution, creation and cookie management, plus the request
//! metadata / response helpers every endpoint uses.

use std::net::SocketAddr;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, FromRequest, FromRequestParts, Request};
use axum::http::header::{LOCATION, SET_COOKIE, USER_AGENT};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{Duration, Utc};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

use crate::context::Auth;
use crate::cookies::get_signed_cookie;
use crate::crypto::generate_id;
use crate::db::Record;
use crate::error::{AuthError, Result};
use crate::models::{ts_value, Session, SessionWithUser, User};

// ---- request metadata ------------------------------------------------------------------

/// Headers and client IP of the incoming request.
#[derive(Clone, Debug, Default)]
pub struct RequestMeta {
    pub headers: HeaderMap,
    pub ip: Option<String>,
}

impl RequestMeta {
    pub fn new(headers: HeaderMap) -> Self {
        Self { headers, ip: None }
    }

    pub fn user_agent(&self) -> Option<String> {
        self.headers.get(USER_AGENT).and_then(|v| v.to_str().ok()).map(str::to_string)
    }

    pub(crate) fn from_parts(auth: &Auth, parts: &Parts) -> Self {
        Self { headers: parts.headers.clone(), ip: client_ip(auth, &parts.headers, parts.extensions.get()) }
    }
}

pub(crate) fn client_ip(auth: &Auth, headers: &HeaderMap, connect: Option<&ConnectInfo<SocketAddr>>) -> Option<String> {
    for name in &auth.options.advanced.ip_address_headers {
        if let Some(v) = headers.get(name.as_str()).and_then(|v| v.to_str().ok()) {
            if let Some(first) = v.split(',').map(str::trim).find(|s| !s.is_empty()) {
                return Some(first.to_string());
            }
        }
    }
    connect.map(|c| c.0.ip().to_string())
}

impl FromRequestParts<Auth> for RequestMeta {
    type Rejection = AuthError;
    async fn from_request_parts(parts: &mut Parts, auth: &Auth) -> Result<Self> {
        Ok(Self::from_parts(auth, parts))
    }
}

/// JSON body extractor that reports errors in the standard error shape and
/// treats an empty body as `{}`.
pub struct JsonBody<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for JsonBody<T> {
    type Rejection = AuthError;
    async fn from_request(req: Request, state: &S) -> Result<Self> {
        let bytes = Bytes::from_request(req, state).await.map_err(|e| AuthError::validation(e.to_string()))?;
        let slice: &[u8] = if bytes.iter().all(u8::is_ascii_whitespace) { b"{}" } else { &bytes };
        serde_json::from_slice(slice).map(JsonBody).map_err(|e| AuthError::validation(format!("Invalid body: {e}")))
    }
}

// ---- responses -------------------------------------------------------------------------

/// Endpoint result: JSON body (or redirect) plus cookies to set. Returned by
/// every endpoint function, so endpoints can also be called server-side.
#[derive(Debug)]
pub struct ApiResponse<T> {
    pub status: StatusCode,
    pub body: T,
    pub cookies: Vec<String>,
    pub headers: HeaderMap,
    pub redirect: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn ok(body: T) -> Self {
        Self { status: StatusCode::OK, body, cookies: Vec::new(), headers: HeaderMap::new(), redirect: None }
    }

    pub fn with_cookies(mut self, cookies: impl IntoIterator<Item = String>) -> Self {
        self.cookies.extend(cookies);
        self
    }

    pub fn redirect(mut self, url: impl Into<String>) -> Self {
        self.redirect = Some(url.into());
        self
    }
}

impl ApiResponse<Value> {
    pub fn redirect_to(url: impl Into<String>) -> Self {
        Self::ok(Value::Null).redirect(url)
    }
}

impl<T: Serialize> IntoResponse for ApiResponse<T> {
    fn into_response(self) -> Response {
        let mut res = match &self.redirect {
            Some(url) => {
                let mut r = StatusCode::FOUND.into_response();
                if let Ok(v) = HeaderValue::from_str(url) {
                    r.headers_mut().insert(LOCATION, v);
                }
                r
            }
            None => (self.status, Json(&self.body)).into_response(),
        };
        res.headers_mut().extend(self.headers);
        for c in self.cookies {
            if let Ok(v) = HeaderValue::from_str(&c) {
                res.headers_mut().append(SET_COOKIE, v);
            }
        }
        res
    }
}

// ---- sessions --------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct SessionLookup {
    pub data: Option<SessionWithUser>,
    /// Cookies to send back (refreshed or cleared session cookie).
    pub cookies: Vec<String>,
}

/// Find the raw session token for a request: signed session cookie first,
/// then plugins (e.g. bearer).
pub async fn resolve_session_token(auth: &Auth, headers: &HeaderMap) -> Option<(String, bool)> {
    if let Some(t) = get_signed_cookie(headers, &auth.cookies.session_token, auth.secret()) {
        return Some((t, true));
    }
    for p in &auth.plugins {
        if let Some(t) = p.resolve_session_token(auth, headers).await {
            return Some((t, false));
        }
    }
    None
}

/// Look up the current session. When `refresh` is true and the session is
/// older than `update_age`, its expiry is extended and the cookie re-issued.
pub async fn get_session(auth: &Auth, headers: &HeaderMap, refresh: bool) -> Result<SessionLookup> {
    let Some((token, from_cookie)) = resolve_session_token(auth, headers).await else {
        return Ok(SessionLookup::default());
    };
    let clear = |from_cookie: bool| if from_cookie { clear_session_cookies(auth) } else { Vec::new() };
    let Some((mut session, user)) = auth.db.find_session(&token).await? else {
        return Ok(SessionLookup { data: None, cookies: clear(from_cookie) });
    };
    let now = Utc::now();
    if session.expires_at <= now {
        auth.db.delete_session(&token).await?;
        return Ok(SessionLookup { data: None, cookies: clear(from_cookie) });
    }

    let mut cookies = Vec::new();
    let opts = &auth.options.session;
    let dont_remember = get_signed_cookie(headers, &auth.cookies.dont_remember, auth.secret()).is_some();
    let due = session.expires_at - Duration::seconds(opts.expires_in) + Duration::seconds(opts.update_age) <= now;
    if refresh && !opts.disable_session_refresh && due {
        let mut data = Record::new();
        data.insert("expiresAt".into(), ts_value(&(now + Duration::seconds(opts.expires_in))));
        if let Some(updated) = auth.db.update_session(&token, data).await? {
            session = updated;
        }
        if from_cookie {
            let max_age = (!dont_remember).then_some(opts.expires_in);
            cookies.push(auth.cookies.set_signed(&auth.cookies.session_token, &token, auth.secret(), max_age));
        }
    }
    Ok(SessionLookup { data: Some(SessionWithUser { session, user: auth.public_user(user) }), cookies })
}

pub async fn require_session(auth: &Auth, headers: &HeaderMap) -> Result<SessionWithUser> {
    get_session(auth, headers, false).await?.data.ok_or_else(AuthError::unauthorized)
}

/// Create a session for `user` and the cookies that carry it.
/// `dont_remember` makes it a browser-session cookie with a 1 day lifetime.
pub async fn create_session(auth: &Auth, user: &User, meta: &RequestMeta, dont_remember: bool) -> Result<(Session, Vec<String>)> {
    let lifetime = if dont_remember { 60 * 60 * 24 } else { auth.options.session.expires_in };
    let ip = if auth.options.advanced.disable_ip_tracking { None } else { meta.ip.clone() };
    let token = generate_id();
    let session = auth.db.create_session(&user.id, token, Utc::now() + Duration::seconds(lifetime), ip, meta.user_agent()).await?;
    Ok((session.clone(), session_cookies(auth, &session, dont_remember)))
}

pub fn session_cookies(auth: &Auth, session: &Session, dont_remember: bool) -> Vec<String> {
    let c = &auth.cookies;
    let max_age = (!dont_remember).then_some(auth.options.session.expires_in);
    let mut out = vec![c.set_signed(&c.session_token, &session.token, auth.secret(), max_age)];
    if dont_remember {
        out.push(c.set_signed(&c.dont_remember, "true", auth.secret(), None));
    }
    out
}

pub fn clear_session_cookies(auth: &Auth) -> Vec<String> {
    vec![auth.cookies.clear(&auth.cookies.session_token), auth.cookies.clear(&auth.cookies.dont_remember)]
}

/// A session is fresh if it was created within `session.fresh_age`.
pub fn is_fresh(auth: &Auth, session: &Session) -> bool {
    let fresh_age = auth.options.session.fresh_age;
    fresh_age == 0 || Utc::now() - session.created_at <= Duration::seconds(fresh_age)
}
