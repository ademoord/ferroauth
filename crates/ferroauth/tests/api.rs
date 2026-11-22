mod common;

use axum::http::StatusCode;
use common::*;
use ferroauth::options::*;
use ferroauth::plugins::{Bearer, MagicLink, MagicLinkEmail, Username};
use ferroauth::schema::Field;
use ferroauth::Auth;
use serde_json::{json, Value};

async fn client(options: AuthOptions) -> Client {
    Client::new(Auth::builder(options).build().await.unwrap())
}

#[tokio::test]
async fn sign_up_sign_in_session_sign_out() {
    let mut c = client(base_options()).await;

    let res = c.sign_up("Alice@Example.com", "password123").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_eq!(res.body["user"]["email"], "alice@example.com");
    assert_eq!(res.body["user"]["emailVerified"], false);
    assert!(res.body["token"].is_string());
    assert!(c.cookies.contains_key("ferroauth.session_token"));

    let s = c.get("/get-session").await;
    assert_eq!(s.body["user"]["email"], "alice@example.com");
    assert_eq!(s.body["session"]["token"], res.body["token"]);

    let out = c.post("/sign-out", json!({})).await;
    assert_eq!(out.body, json!({ "success": true }));
    assert!(c.cookies.is_empty());
    assert_eq!(c.get("/get-session").await.body, Value::Null);

    let res = c.post("/sign-in/email", json!({ "email": "alice@example.com", "password": "password123" })).await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.body["redirect"], false);
    assert_eq!(c.get("/get-session").await.body["user"]["name"], "Test User");
}

#[tokio::test]
async fn sign_in_and_sign_up_errors() {
    let mut c = client(base_options()).await;
    c.sign_up("bob@example.com", "password123").await;

    let dup = c.fork().sign_up("BOB@example.com", "password123").await;
    assert_eq!(dup.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(dup.body["code"], "USER_ALREADY_EXISTS");

    let short = c.fork().sign_up("short@example.com", "short").await;
    assert_eq!(short.body["code"], "PASSWORD_TOO_SHORT");

    let bad_email = c.fork().sign_up("not-an-email", "password123").await;
    assert_eq!(bad_email.body["code"], "INVALID_EMAIL");

    let mut other = c.fork();
    let wrong = other.post("/sign-in/email", json!({ "email": "bob@example.com", "password": "nope-nope" })).await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.body["code"], "INVALID_EMAIL_OR_PASSWORD");
    let unknown = other.post("/sign-in/email", json!({ "email": "ghost@example.com", "password": "password123" })).await;
    assert_eq!(unknown.body["code"], "INVALID_EMAIL_OR_PASSWORD");

    let missing = other.post("/sign-in/email", json!({ "email": "bob@example.com" })).await;
    assert_eq!(missing.body["code"], "VALIDATION_ERROR");
}

#[tokio::test]
async fn sign_up_disabled_and_no_auto_sign_in() {
    let mut opts = base_options();
    opts.email_and_password.auto_sign_in = false;
    let mut c = client(opts).await;
    let res = c.sign_up("carol@example.com", "password123").await;
    assert_eq!(res.body["token"], Value::Null);
    assert!(c.cookies.is_empty());

    let mut opts = base_options();
    opts.email_and_password.disable_sign_up = true;
    let mut c = client(opts).await;
    assert_eq!(c.sign_up("dave@example.com", "password123").await.body["code"], "SIGN_UP_DISABLED");
}

#[tokio::test]
async fn csrf_origin_checks() {
    let mut c = client(base_options()).await;
    c.sign_up("eve@example.com", "password123").await;

    c.origin = Some("https://evil.example".into());
    let res = c.post("/sign-out", json!({})).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert_eq!(res.body["code"], "INVALID_ORIGIN");

    c.origin = None;
    let res = c.post("/sign-out", json!({})).await;
    assert_eq!(res.body["code"], "MISSING_OR_NULL_ORIGIN");

    // Open-redirect protection on callback URLs.
    c.origin = Some(ORIGIN.into());
    let res = c
        .post("/sign-in/email", json!({ "email": "eve@example.com", "password": "password123", "callbackURL": "https://evil.example/x" }))
        .await;
    assert_eq!(res.body["code"], "INVALID_CALLBACK_URL");
    let res =
        c.post("/sign-in/email", json!({ "email": "eve@example.com", "password": "password123", "callbackURL": "/dashboard" })).await;
    assert_eq!(res.body["redirect"], true);
    assert_eq!(res.body["url"], "/dashboard");
}

#[tokio::test]
async fn trusted_origins_and_wildcards() {
    let mut opts = base_options();
    opts.trusted_origins = vec!["https://*.myapp.com".into()];
    let mut c = client(opts).await;
    c.origin = Some("https://app.myapp.com".into());
    assert_eq!(c.sign_up("w@example.com", "password123").await.status, StatusCode::OK);
    c.origin = Some("https://myapp.com.evil.com".into());
    assert_eq!(c.post("/sign-out", json!({})).await.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn sessions_listing_and_revocation() {
    let mut a = client(base_options()).await;
    a.sign_up("frank@example.com", "password123").await;
    let mut b = a.fork();
    b.post("/sign-in/email", json!({ "email": "frank@example.com", "password": "password123" })).await;

    let list = a.get("/list-sessions").await;
    assert_eq!(list.body.as_array().unwrap().len(), 2);

    let b_token = b.get("/get-session").await.body["session"]["token"].clone();
    assert_eq!(a.post("/revoke-session", json!({ "token": b_token })).await.body["status"], true);
    assert_eq!(b.get("/get-session").await.body, Value::Null);

    b.post("/sign-in/email", json!({ "email": "frank@example.com", "password": "password123" })).await;
    a.post("/revoke-other-sessions", json!({})).await;
    assert_eq!(b.get("/get-session").await.body, Value::Null);
    assert!(a.get("/get-session").await.body["user"].is_object());

    a.post("/revoke-sessions", json!({})).await;
    assert_eq!(a.get("/get-session").await.body, Value::Null);
    assert_eq!(a.get("/list-sessions").await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn remember_me_false_uses_browser_session_cookie() {
    let mut c = client(base_options()).await;
    c.sign_up("rm@example.com", "password123").await;
    c.cookies.clear();
    let res = c.post("/sign-in/email", json!({ "email": "rm@example.com", "password": "password123", "rememberMe": false })).await;
    let set_cookies: Vec<_> = res.headers.get_all("set-cookie").iter().map(|v| v.to_str().unwrap().to_string()).collect();
    let session_cookie = set_cookies.iter().find(|c| c.starts_with("ferroauth.session_token=")).unwrap();
    assert!(!session_cookie.contains("Max-Age"), "{session_cookie}");
    assert!(set_cookies.iter().any(|c| c.starts_with("ferroauth.dont_remember=")));
}

#[tokio::test]
async fn session_refresh_extends_expiry() {
    let mut opts = base_options();
    opts.session.expires_in = 3600;
    opts.session.update_age = 0; // always due
    let mut c = client(opts).await;
    c.sign_up("ref@example.com", "password123").await;
    let first = c.get("/get-session").await;
    assert!(first.headers.get("set-cookie").is_some(), "refresh should reissue the cookie");
    let no_refresh = c.get("/get-session?disableRefresh=true").await;
    assert!(no_refresh.headers.get("set-cookie").is_none());
}

#[tokio::test]
async fn update_user_and_additional_fields() {
    let mut opts = base_options();
    opts.user.additional_fields = vec![Field::string("role").optional().input(), Field::string("internalNote").optional().hidden()];
    let mut c = client(opts).await;
    let res = c.post("/sign-up/email", json!({ "name": "G", "email": "g@example.com", "password": "password123", "role": "admin", "emailVerified": true })).await;
    assert_eq!(res.body["user"]["role"], "admin");
    assert_eq!(res.body["user"]["emailVerified"], false, "non-input fields are ignored");

    assert_eq!(c.post("/update-user", json!({ "name": "Grace", "role": "editor" })).await.body["status"], true);
    let s = c.get("/get-session").await;
    assert_eq!(s.body["user"]["name"], "Grace");
    assert_eq!(s.body["user"]["role"], "editor");
    assert!(s.body["user"].get("internalNote").is_none(), "hidden fields are not returned");

    assert_eq!(c.post("/update-user", json!({ "email": "x@example.com" })).await.body["code"], "EMAIL_CAN_NOT_BE_UPDATED");
}

#[tokio::test]
async fn change_password_revokes_other_sessions() {
    let mut a = client(base_options()).await;
    a.sign_up("h@example.com", "password123").await;
    let mut b = a.fork();
    b.post("/sign-in/email", json!({ "email": "h@example.com", "password": "password123" })).await;

    let bad = a.post("/change-password", json!({ "currentPassword": "wrong-pass", "newPassword": "newpassword1" })).await;
    assert_eq!(bad.body["code"], "INVALID_PASSWORD");

    let ok = a
        .post("/change-password", json!({ "currentPassword": "password123", "newPassword": "newpassword1", "revokeOtherSessions": true }))
        .await;
    assert!(ok.body["token"].is_string());
    assert_eq!(b.get("/get-session").await.body, Value::Null);
    assert!(a.get("/get-session").await.body["user"].is_object());

    let mut c = a.fork();
    assert_eq!(c.post("/sign-in/email", json!({ "email": "h@example.com", "password": "newpassword1" })).await.status, StatusCode::OK);
}

#[tokio::test]
async fn password_reset_flow() {
    let outbox = Outbox::<ResetPasswordEmail>::new();
    let mut opts = base_options();
    opts.email_and_password.send_reset_password = Some(outbox.callback());
    opts.email_and_password.revoke_sessions_on_password_reset = true;
    let mut c = client(opts).await;
    c.sign_up("ivy@example.com", "password123").await;

    let res = c.post("/request-password-reset", json!({ "email": "ivy@example.com", "redirectTo": "/reset" })).await;
    assert_eq!(res.body["status"], true);
    let mail = outbox.last().unwrap();
    assert_eq!(mail.user.email, "ivy@example.com");

    // Unknown emails get the same response and no mail.
    c.post("/forget-password", json!({ "email": "nobody@example.com" })).await;
    assert_eq!(outbox.len(), 1);

    let link = c.get(&mail.url).await;
    assert_eq!(link.status, StatusCode::FOUND);
    assert_eq!(link.location(), format!("/reset?token={}", mail.token));

    let res = c.post("/reset-password", json!({ "token": mail.token, "newPassword": "brand-new-pass" })).await;
    assert_eq!(res.body["status"], true);
    assert_eq!(c.get("/get-session").await.body, Value::Null, "sessions revoked");
    let reuse = c.post("/reset-password", json!({ "token": mail.token, "newPassword": "another-pass" })).await;
    assert_eq!(reuse.body["code"], "INVALID_TOKEN");

    let mut d = c.fork();
    assert_eq!(d.post("/sign-in/email", json!({ "email": "ivy@example.com", "password": "brand-new-pass" })).await.status, StatusCode::OK);
}

#[tokio::test]
async fn email_verification_required() {
    let outbox = Outbox::<VerificationEmail>::new();
    let mut opts = base_options();
    opts.email_and_password.require_email_verification = true;
    opts.email_verification.send_verification_email = Some(outbox.callback());
    opts.email_verification.auto_sign_in_after_verification = true;
    let mut c = client(opts).await;

    let res = c.post("/sign-up/email", json!({ "name": "J", "email": "j@example.com", "password": "password123", "callbackURL": "/welcome" })).await;
    assert_eq!(res.body["token"], Value::Null);
    let mail = outbox.last().unwrap();
    assert!(mail.url.contains("callbackURL=%2Fwelcome"), "{}", mail.url);

    let res = c.post("/sign-in/email", json!({ "email": "j@example.com", "password": "password123" })).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert_eq!(res.body["code"], "EMAIL_NOT_VERIFIED");

    let verify = c.get(&mail.url).await;
    assert_eq!(verify.status, StatusCode::FOUND);
    assert_eq!(verify.location(), "/welcome");
    let s = c.get("/get-session").await;
    assert_eq!(s.body["user"]["emailVerified"], true, "auto sign-in after verification");

    let bad = c.get("/verify-email?token=garbage&callbackURL=/welcome").await;
    assert_eq!(bad.location(), "/welcome?error=invalid_token");
}

#[tokio::test]
async fn change_email_flows() {
    let outbox = Outbox::<VerificationEmail>::new();
    let change_box = Outbox::<ChangeEmailVerification>::new();
    let mut opts = base_options();
    opts.email_verification.send_verification_email = Some(outbox.callback());
    opts.user.change_email = ChangeEmailOptions { enabled: true, send_change_email_verification: Some(change_box.callback()) };
    let mut c = client(opts).await;
    c.sign_up("k@example.com", "password123").await;

    // Unverified: changes immediately.
    assert_eq!(c.post("/change-email", json!({ "newEmail": "k2@example.com" })).await.body["status"], true);
    assert_eq!(c.get("/get-session").await.body["user"]["email"], "k2@example.com");

    // Verify, then change again: needs confirmation from the current address.
    c.get(&outbox.last().unwrap().url).await;
    assert_eq!(c.get("/get-session").await.body["user"]["emailVerified"], true);
    c.post("/change-email", json!({ "newEmail": "k3@example.com" })).await;
    assert_eq!(c.get("/get-session").await.body["user"]["email"], "k2@example.com");
    let confirm = change_box.last().unwrap();
    assert_eq!(confirm.new_email, "k3@example.com");
    c.get(&confirm.url).await;
    let user = c.get("/get-session").await.body["user"].clone();
    assert_eq!(user["email"], "k3@example.com");
    assert_eq!(user["emailVerified"], false);
}

#[tokio::test]
async fn delete_user() {
    let mut opts = base_options();
    opts.user.delete_user.enabled = true;
    let mut c = client(opts).await;
    c.sign_up("l@example.com", "password123").await;
    assert_eq!(c.post("/delete-user", json!({ "password": "wrong-password" })).await.body["code"], "INVALID_PASSWORD");
    let res = c.post("/delete-user", json!({ "password": "password123" })).await;
    assert_eq!(res.body["success"], true);
    assert_eq!(c.get("/get-session").await.body, Value::Null);
    assert!(c.auth.db.find_user_by_email("l@example.com").await.unwrap().is_none());
    assert!(c.auth.db.find_accounts("whatever").await.unwrap().is_empty());
}

#[tokio::test]
async fn rate_limiting_by_ip() {
    let mut opts = base_options();
    opts.rate_limit = RateLimitOptions::default();
    let mut c = client(opts).await;
    c.extra_headers.push(("x-forwarded-for".into(), "203.0.113.7".into()));
    for _ in 0..3 {
        c.post("/sign-in/email", json!({ "email": "m@example.com", "password": "password123" })).await;
    }
    let res = c.post("/sign-in/email", json!({ "email": "m@example.com", "password": "password123" })).await;
    assert_eq!(res.status, StatusCode::TOO_MANY_REQUESTS);
    c.extra_headers = vec![("x-forwarded-for".into(), "203.0.113.8".into())];
    assert_ne!(c.post("/sign-in/email", json!({ "email": "m@example.com", "password": "password123" })).await.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn username_plugin() {
    let auth = Auth::builder(base_options()).plugin(Username::new()).build().await.unwrap();
    let mut c = Client::new(auth);
    let res = c.post("/sign-up/email", json!({ "name": "N", "email": "n@example.com", "password": "password123", "username": "Neo_One" })).await;
    assert_eq!(res.body["user"]["username"], "neo_one");
    assert_eq!(res.body["user"]["displayUsername"], "Neo_One");

    let taken = c.fork().post("/sign-up/email", json!({ "name": "X", "email": "x@example.com", "password": "password123", "username": "NEO_ONE" })).await;
    assert_eq!(taken.body["code"], "USERNAME_IS_ALREADY_TAKEN");
    let invalid = c.fork().post("/sign-up/email", json!({ "name": "X", "email": "x@example.com", "password": "password123", "username": "a b" })).await;
    assert_eq!(invalid.body["code"], "INVALID_USERNAME");

    let mut d = c.fork();
    assert_eq!(d.post("/is-username-available", json!({ "username": "neo_one" })).await.body["available"], false);
    assert_eq!(d.post("/is-username-available", json!({ "username": "trinity" })).await.body["available"], true);
    let res = d.post("/sign-in/username", json!({ "username": "Neo_One", "password": "password123" })).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let res = d.fork().post("/sign-in/username", json!({ "username": "neo_one", "password": "bad-password" })).await;
    assert_eq!(res.body["code"], "INVALID_USERNAME_OR_PASSWORD");

    // Updating to your own username is fine; someone else's is not.
    assert_eq!(c.post("/update-user", json!({ "username": "neo_one" })).await.body["status"], true);
    let mut other = c.fork();
    other.post("/sign-up/email", json!({ "name": "T", "email": "t@example.com", "password": "password123", "username": "trinity" })).await;
    assert_eq!(other.post("/update-user", json!({ "username": "neo_one" })).await.body["code"], "USERNAME_IS_ALREADY_TAKEN");
}

#[tokio::test]
async fn bearer_plugin() {
    let auth = Auth::builder(base_options()).plugin(Bearer::new()).build().await.unwrap();
    let mut c = Client::new(auth);
    let res = c.sign_up("o@example.com", "password123").await;
    let header_token = res.headers.get("set-auth-token").unwrap().to_str().unwrap().to_string();
    assert!(header_token.starts_with(res.body["token"].as_str().unwrap()));

    let mut api = c.fork();
    api.origin = None;
    api.extra_headers.push(("authorization".into(), format!("Bearer {header_token}")));
    assert_eq!(api.get("/get-session").await.body["user"]["email"], "o@example.com");

    let mut raw = c.fork();
    raw.extra_headers.push(("authorization".into(), format!("Bearer {}", res.body["token"].as_str().unwrap())));
    assert_eq!(raw.get("/get-session").await.body["user"]["email"], "o@example.com");

    let mut forged = c.fork();
    forged.extra_headers.push(("authorization".into(), "Bearer abc.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into()));
    assert_eq!(forged.get("/get-session").await.body, Value::Null);
}

#[tokio::test]
async fn magic_link_plugin() {
    let outbox = Outbox::<MagicLinkEmail>::new();
    let auth = Auth::builder(base_options()).plugin(MagicLink::new(outbox.callback())).build().await.unwrap();
    let mut c = Client::new(auth);
    let res = c.post("/sign-in/magic-link", json!({ "email": "p@example.com", "name": "Pat", "callbackURL": "/app", "newUserCallbackURL": "/welcome" })).await;
    assert_eq!(res.body["status"], true);
    let mail = outbox.last().unwrap();
    let verify = c.get(&mail.url).await;
    assert_eq!(verify.status, StatusCode::FOUND);
    assert_eq!(verify.location(), "/welcome");
    let s = c.get("/get-session").await;
    assert_eq!(s.body["user"]["name"], "Pat");
    assert_eq!(s.body["user"]["emailVerified"], true);

    // Token is single use.
    let again = c.fork().get(&mail.url).await;
    assert_eq!(again.location(), "/app?error=INVALID_TOKEN");
}

#[tokio::test]
async fn cookie_format() {
    let mut c = client(base_options()).await;
    let res = c.sign_up("q@example.com", "password123").await;
    let token = res.body["token"].as_str().unwrap();
    let raw = res.headers.get("set-cookie").unwrap().to_str().unwrap();
    assert!(raw.contains("HttpOnly") && raw.contains("SameSite=Lax") && raw.contains("Path=/") && raw.contains("Max-Age=604800"));
    // `token.base64sig`, URL-encoded like encodeURIComponent.
    let value = ferroauth::cookies::parse_set_cookie(raw, "ferroauth.session_token").unwrap();
    let expected = ferroauth::crypto::sign_value("test-secret-test-secret-test-secret-0123", token);
    assert_eq!(value, expected);

    let mut opts = base_options();
    opts.base_url = "https://secure.example".into();
    let auth = Auth::builder(opts).build().await.unwrap();
    assert_eq!(auth.cookies.session_token, "__Secure-ferroauth.session_token");
}

#[tokio::test]
async fn server_side_api() {
    let auth = Auth::builder(base_options()).build().await.unwrap();
    let meta = ferroauth::RequestMeta::default();
    let res = ferroauth::routes::email_password::sign_up_email(
        &auth,
        &meta,
        serde_json::from_value(json!({ "name": "S", "email": "s@example.com", "password": "password123" })).unwrap(),
    )
    .await
    .unwrap();
    let mut headers = axum::http::HeaderMap::new();
    let cookie = res.cookies[0].split(';').next().unwrap().to_string();
    headers.insert("cookie", cookie.parse().unwrap());
    let session = auth.get_session(&headers).await.unwrap().unwrap();
    assert_eq!(session.user.email, "s@example.com");
    ferroauth::routes::user::set_password(&auth, &session.user.id, "password456").await.unwrap_err();
}
