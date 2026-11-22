//! Cookie handling. Names are `{prefix}.session_token` etc. (prefixed with
//! `__Secure-` on https); signed values are
//! `encodeURIComponent(token + "." + base64(hmac))`.

use std::collections::HashMap;

use axum::http::header::COOKIE;
use axum::http::HeaderMap;
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};

use crate::crypto::{sign_value, verify_signed_value};

/// Characters `encodeURIComponent` escapes.
const URI_COMPONENT: &AsciiSet =
    &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'!').remove(b'~').remove(b'*').remove(b'\'').remove(b'(').remove(b')');

pub fn encode_uri_component(s: &str) -> String {
    utf8_percent_encode(s, URI_COMPONENT).to_string()
}

#[derive(Debug, Clone)]
pub struct CookieConfig {
    pub secure: bool,
    pub domain: Option<String>,
    pub session_token: String,
    pub dont_remember: String,
    pub state: String,
    name_prefix: String,
}

impl CookieConfig {
    pub fn new(prefix: &str, secure: bool, domain: Option<String>) -> Self {
        let name_prefix = format!("{}{prefix}.", if secure { "__Secure-" } else { "" });
        let name = |n: &str| format!("{name_prefix}{n}");
        Self {
            secure,
            domain,
            session_token: name("session_token"),
            dont_remember: name("dont_remember"),
            state: name("state"),
            name_prefix: name_prefix.clone(),
        }
    }

    /// Full name for an auth cookie, e.g. `name("two_factor")` → `ferroauth.two_factor`.
    pub fn name(&self, short: &str) -> String {
        format!("{}{short}", self.name_prefix)
    }

    /// Build a `Set-Cookie` header value. `max_age: None` makes a browser-session cookie.
    pub fn set(&self, name: &str, value: &str, max_age: Option<i64>) -> String {
        let mut c = format!("{name}={}; Path=/; HttpOnly; SameSite=Lax", encode_uri_component(value));
        if let Some(age) = max_age {
            c.push_str(&format!("; Max-Age={age}"));
        }
        if self.secure {
            c.push_str("; Secure");
        }
        if let Some(d) = &self.domain {
            c.push_str(&format!("; Domain={d}"));
        }
        c
    }

    pub fn set_signed(&self, name: &str, value: &str, secret: &str, max_age: Option<i64>) -> String {
        self.set(name, &sign_value(secret, value), max_age)
    }

    pub fn clear(&self, name: &str) -> String {
        self.set(name, "", Some(0))
    }
}

/// Parse the `Cookie` request header(s) into name → decoded value.
pub fn parse_cookies(headers: &HeaderMap) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for header in headers.get_all(COOKIE) {
        let Ok(s) = header.to_str() else { continue };
        for pair in s.split(';') {
            if let Some((k, v)) = pair.trim().split_once('=') {
                let v = v.trim().trim_matches('"');
                let decoded = percent_decode_str(v).decode_utf8_lossy().into_owned();
                out.entry(k.trim().to_string()).or_insert(decoded);
            }
        }
    }
    out
}

pub fn get_signed_cookie(headers: &HeaderMap, name: &str, secret: &str) -> Option<String> {
    parse_cookies(headers).get(name).and_then(|v| verify_signed_value(secret, v))
}

/// Extract the value of cookie `name` from a `Set-Cookie` header value.
pub fn parse_set_cookie(set_cookie: &str, name: &str) -> Option<String> {
    let first = set_cookie.split(';').next()?;
    let (k, v) = first.split_once('=')?;
    (k.trim() == name).then(|| percent_decode_str(v.trim()).decode_utf8_lossy().into_owned())
}
