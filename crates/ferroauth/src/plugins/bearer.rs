//! Bearer plugin: authenticate with `Authorization: Bearer <token>` instead of
//! cookies. Responses that create a session carry the token in a
//! `set-auth-token` header.

use async_trait::async_trait;
use axum::http::header::{ACCESS_CONTROL_EXPOSE_HEADERS, AUTHORIZATION, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue};
use axum::response::Response;

use super::{Plugin, RequestInfo};
use crate::context::Auth;
use crate::cookies::parse_set_cookie;
use crate::crypto::verify_signed_value;

#[derive(Debug, Clone, Default)]
pub struct Bearer {
    /// Only accept signed tokens (`token.signature`). Default false.
    pub require_signature: bool,
}

impl Bearer {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Plugin for Bearer {
    fn id(&self) -> &'static str {
        "bearer"
    }

    async fn resolve_session_token(&self, auth: &Auth, headers: &HeaderMap) -> Option<String> {
        let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
        let token = value.strip_prefix("Bearer ").or_else(|| value.strip_prefix("bearer "))?.trim();
        let token = percent_encoding::percent_decode_str(token).decode_utf8_lossy();
        if let Some(raw) = verify_signed_value(auth.secret(), &token) {
            return Some(raw);
        }
        (!self.require_signature && !token.contains('.') && !token.is_empty()).then(|| token.into_owned())
    }

    async fn on_response(&self, auth: &Auth, _req: &RequestInfo, mut res: Response) -> Response {
        let token = res
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|c| parse_set_cookie(c, &auth.cookies.session_token))
            .filter(|t| !t.is_empty());
        if let Some(token) = token {
            if let Ok(v) = HeaderValue::from_str(&token) {
                res.headers_mut().insert("set-auth-token", v);
                res.headers_mut().append(ACCESS_CONTROL_EXPOSE_HEADERS, HeaderValue::from_static("set-auth-token"));
            }
        }
        res
    }
}
