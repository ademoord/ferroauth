mod common;

use async_trait::async_trait;
use axum::http::StatusCode;
use common::*;
use ferroauth::oauth::{AuthorizationRequest, OAuthProvider, OAuthTokens, OAuthUserInfo};
use ferroauth::{Auth, AuthError};
use serde_json::{json, Value};
use url::Url;

/// A provider that never touches the network: code "good-<email>" is valid.
struct Mock {
    verified: bool,
}

#[async_trait]
impl OAuthProvider for Mock {
    fn id(&self) -> &str {
        "mock"
    }
    fn authorization_url(&self, req: AuthorizationRequest<'_>) -> ferroauth::Result<String> {
        let mut u = Url::parse("https://mock.example/authorize").unwrap();
        u.query_pairs_mut().append_pair("state", req.state).append_pair("redirect_uri", req.redirect_uri);
        Ok(u.to_string())
    }
    async fn exchange_code(&self, _: &reqwest::Client, code: &str, verifier: &str, _: &str) -> ferroauth::Result<OAuthTokens> {
        assert_eq!(verifier.len(), 64);
        let email = code.strip_prefix("good-").ok_or_else(AuthError::invalid_token)?;
        Ok(OAuthTokens::from_response(json!({ "access_token": format!("at-{email}"), "expires_in": 3600, "scope": "read email" })))
    }
    async fn user_info(&self, _: &reqwest::Client, t: &OAuthTokens) -> ferroauth::Result<OAuthUserInfo> {
        let email = t.access_token.as_deref().unwrap().strip_prefix("at-").unwrap().to_string();
        Ok(OAuthUserInfo { id: format!("mock-{email}"), name: "Mock User".into(), email: Some(email), email_verified: self.verified, image: None })
    }
}

async fn start(c: &mut Client, body: Value) -> String {
    let res = c.post("/sign-in/social", body).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_eq!(res.body["redirect"], true);
    let url = Url::parse(res.body["url"].as_str().unwrap()).unwrap();
    assert_eq!(
        url.query_pairs().find(|(k, _)| k == "redirect_uri").unwrap().1,
        "http://localhost:3000/api/auth/callback/mock"
    );
    url.query_pairs().find(|(k, _)| k == "state").unwrap().1.into_owned()
}

#[tokio::test]
async fn social_sign_in_creates_and_reuses_user() {
    let auth = Auth::builder(base_options()).social_provider(Mock { verified: true }).build().await.unwrap();
    let mut c = Client::new(auth);

    let state = start(&mut c, json!({ "provider": "mock", "callbackURL": "/home", "newUserCallbackURL": "/onboarding" })).await;
    let res = c.get(&format!("/callback/mock?code=good-r@example.com&state={state}")).await;
    assert_eq!(res.status, StatusCode::FOUND);
    assert_eq!(res.location(), "/onboarding");
    let s = c.get("/get-session").await;
    assert_eq!(s.body["user"]["email"], "r@example.com");
    assert_eq!(s.body["user"]["emailVerified"], true);

    let accounts = c.get("/list-accounts").await;
    assert_eq!(accounts.body[0]["providerId"], "mock");
    assert_eq!(accounts.body[0]["scopes"], json!(["read", "email"]));
    assert!(accounts.body[0].get("accessToken").is_none());

    // Second sign-in goes to callbackURL, same user.
    let mut d = c.fork();
    let state = start(&mut d, json!({ "provider": "mock", "callbackURL": "/home", "newUserCallbackURL": "/onboarding" })).await;
    let res = d.get(&format!("/callback/mock?code=good-r@example.com&state={state}")).await;
    assert_eq!(res.location(), "/home");
    assert_eq!(d.get("/get-session").await.body["user"]["id"], s.body["user"]["id"]);

    // Can't unlink the only account.
    assert_eq!(c.post("/unlink-account", json!({ "providerId": "mock" })).await.body["code"], "FAILED_TO_UNLINK_LAST_ACCOUNT");
}

#[tokio::test]
async fn callback_rejects_bad_state() {
    let auth = Auth::builder(base_options()).social_provider(Mock { verified: true }).build().await.unwrap();
    let mut c = Client::new(auth);
    let state = start(&mut c, json!({ "provider": "mock", "callbackURL": "/home" })).await;

    // Another browser (no state cookie) replaying the callback.
    let mut attacker = c.fork();
    let res = attacker.get(&format!("/callback/mock?code=good-a@example.com&state={state}")).await;
    assert_eq!(res.location(), "/home?error=state_mismatch");

    let res = c.get("/callback/mock?code=good-a@example.com&state=unknown").await;
    assert_eq!(res.location(), "http://localhost:3000/api/auth/error?error=please_restart_the_process");

    let state = start(&mut c, json!({ "provider": "mock", "errorCallbackURL": "/login" })).await;
    let res = c.get(&format!("/callback/mock?code=bad&state={state}")).await;
    assert_eq!(res.location(), "/login?error=invalid_code");

    assert_eq!(c.post("/sign-in/social", json!({ "provider": "nope" })).await.body["code"], "PROVIDER_NOT_FOUND");
}

#[tokio::test]
async fn account_linking_rules() {
    // Unverified provider email must not take over an existing account.
    let auth = Auth::builder(base_options()).social_provider(Mock { verified: false }).build().await.unwrap();
    let mut c = Client::new(auth);
    c.sign_up("s@example.com", "password123").await;
    let mut other = c.fork();
    let state = start(&mut other, json!({ "provider": "mock" })).await;
    let res = other.get(&format!("/callback/mock?code=good-s@example.com&state={state}")).await;
    assert_eq!(res.location(), "/?error=account_not_linked");

    // Explicit linking from a signed-in session works.
    let res = c.post("/link-social", json!({ "provider": "mock", "callbackURL": "/settings" })).await;
    let url = Url::parse(res.body["url"].as_str().unwrap()).unwrap();
    let state = url.query_pairs().find(|(k, _)| k == "state").unwrap().1.into_owned();
    let res = c.get(&format!("/callback/mock?code=good-s@example.com&state={state}")).await;
    assert_eq!(res.location(), "/settings");
    let accounts = c.get("/list-accounts").await.body;
    assert_eq!(accounts.as_array().unwrap().len(), 2);

    // Now that it's linked, unlinking the credential account is allowed.
    assert_eq!(c.post("/unlink-account", json!({ "providerId": "mock" })).await.body["status"], true);
}
