#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use axum::Router;
use ferroauth::{Auth, AuthOptions, Callback, EmailAndPasswordOptions, RateLimitOptions};
use serde_json::Value;
use tower::ServiceExt;

pub const ORIGIN: &str = "http://localhost:3000";

pub fn base_options() -> AuthOptions {
    AuthOptions {
        base_url: ORIGIN.into(),
        secret: Some("test-secret-test-secret-test-secret-0123".into()),
        email_and_password: EmailAndPasswordOptions { enabled: true, ..Default::default() },
        rate_limit: RateLimitOptions { enabled: false, ..Default::default() },
        ..Default::default()
    }
}

/// Collects payloads sent to a callback (e.g. emails).
#[derive(Clone)]
pub struct Outbox<T>(pub Arc<Mutex<Vec<T>>>);

impl<T: Clone + Send + 'static> Outbox<T> {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }
    pub fn callback(&self) -> Callback<T> {
        let inner = self.0.clone();
        Callback::new(move |t: T| {
            let inner = inner.clone();
            async move { inner.lock().unwrap().push(t) }
        })
    }
    pub fn last(&self) -> Option<T> {
        self.0.lock().unwrap().last().cloned()
    }
    pub fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }
}

pub struct Res {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Value,
}

impl Res {
    pub fn location(&self) -> String {
        self.headers.get(header::LOCATION).map(|v| v.to_str().unwrap().to_string()).unwrap_or_default()
    }
}

/// A tiny browser: keeps cookies, sends the Origin header.
pub struct Client {
    pub app: Router,
    pub auth: Auth,
    pub cookies: HashMap<String, String>,
    pub origin: Option<String>,
    pub extra_headers: Vec<(String, String)>,
}

impl Client {
    pub fn new(auth: Auth) -> Self {
        let app = auth.router().layer(auth.layer());
        Self { app, auth, cookies: HashMap::new(), origin: Some(ORIGIN.into()), extra_headers: Vec::new() }
    }

    pub fn fork(&self) -> Self {
        Self { app: self.app.clone(), auth: self.auth.clone(), cookies: HashMap::new(), origin: self.origin.clone(), extra_headers: Vec::new() }
    }

    pub async fn get(&mut self, path: &str) -> Res {
        self.send(Method::GET, path, None).await
    }

    pub async fn post(&mut self, path: &str, body: Value) -> Res {
        self.send(Method::POST, path, Some(body)).await
    }

    pub async fn send(&mut self, method: Method, path: &str, body: Option<Value>) -> Res {
        let uri = if path.starts_with("http") { path.to_string() } else { format!("/api/auth{path}") };
        let uri = uri.strip_prefix(ORIGIN).map(str::to_string).unwrap_or(uri);
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(o) = &self.origin {
            req = req.header(header::ORIGIN, o);
        }
        if !self.cookies.is_empty() {
            let c: Vec<String> = self.cookies.iter().map(|(k, v)| format!("{k}={v}")).collect();
            req = req.header(header::COOKIE, c.join("; "));
        }
        for (k, v) in &self.extra_headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let req = match body {
            Some(b) => req.header(header::CONTENT_TYPE, "application/json").body(Body::from(b.to_string())).unwrap(),
            None => req.body(Body::empty()).unwrap(),
        };
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        for sc in headers.get_all(header::SET_COOKIE) {
            let sc = sc.to_str().unwrap();
            let (pair, attrs) = sc.split_once(';').unwrap_or((sc, ""));
            let (k, v) = pair.split_once('=').unwrap();
            if attrs.contains("Max-Age=0") {
                self.cookies.remove(k);
            } else {
                self.cookies.insert(k.to_string(), v.to_string());
            }
        }
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        Res { status, headers, body }
    }

    pub async fn sign_up(&mut self, email: &str, password: &str) -> Res {
        self.post("/sign-up/email", serde_json::json!({ "name": "Test User", "email": email, "password": password })).await
    }
}
