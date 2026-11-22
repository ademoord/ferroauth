mod common;

use axum::http::StatusCode;
use common::*;
use ferroauth::crypto::{base32_decode, totp_now};
use ferroauth::plugins::two_factor::{self, OtpStorage, TwoFactorOptions};
use ferroauth::plugins::{TwoFactor, TwoFactorOtp, Username};
use ferroauth::Auth;
use serde_json::{json, Value};

const TWO_FACTOR: &str = "ferroauth.two_factor";
const TRUST: &str = "ferroauth.trust_device";
const SESSION: &str = "ferroauth.session_token";

async fn client_with(opts: TwoFactorOptions) -> Client {
    Client::new(Auth::builder(base_options()).plugin(TwoFactor::with_options(opts)).plugin(Username::new()).build().await.unwrap())
}

fn secret_from_uri(uri: &str) -> Vec<u8> {
    let url = url::Url::parse(uri).unwrap();
    let b32 = url.query_pairs().find(|(k, _)| k == "secret").unwrap().1.into_owned();
    base32_decode(&b32).unwrap()
}

fn code(secret: &[u8]) -> String {
    totp_now(secret, 30, 6)
}

fn wrong_code(secret: &[u8]) -> String {
    let c: u32 = code(secret).parse().unwrap();
    format!("{:06}", (c + 500_000) % 1_000_000)
}

/// Sign up and enable + confirm TOTP. Returns (client, totp secret, backup codes).
async fn user_with_totp(opts: TwoFactorOptions, email: &str) -> (Client, Vec<u8>, Vec<String>) {
    let mut c = client_with(opts).await;
    c.sign_up(email, "password123").await;
    let res = c.post("/two-factor/enable", json!({ "password": "password123" })).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let secret = secret_from_uri(res.body["totpURI"].as_str().unwrap());
    let codes = serde_json::from_value(res.body["backupCodes"].clone()).unwrap();
    let res = c.post("/two-factor/verify-totp", json!({ "code": code(&secret) })).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    (c, secret, codes)
}

async fn sign_in(c: &mut Client, email: &str) -> Value {
    c.post("/sign-in/email", json!({ "email": email, "password": "password123" })).await.body
}

#[tokio::test]
async fn totp_enable_and_sign_in() {
    let mut c = client_with(TwoFactorOptions::default()).await;
    let up = c.sign_up("ada@example.com", "password123").await;
    assert_eq!(up.body["user"]["twoFactorEnabled"], false, "schema default applied");

    assert_eq!(c.post("/two-factor/enable", json!({ "password": "nope-nope" })).await.body["code"], "INVALID_PASSWORD");
    let res = c.post("/two-factor/enable", json!({ "password": "password123", "issuer": "Acme" })).await;
    let uri = res.body["totpURI"].as_str().unwrap();
    assert!(uri.starts_with("otpauth://totp/Acme:ada%40example.com?secret="), "{uri}");
    assert_eq!(res.body["backupCodes"].as_array().unwrap().len(), 10);
    assert!(res.body["backupCodes"][0].as_str().unwrap().contains('-'));
    let secret = secret_from_uri(uri);

    // Not enabled until a code is confirmed.
    assert_eq!(c.get("/get-session").await.body["user"]["twoFactorEnabled"], false);
    let bad = c.post("/two-factor/verify-totp", json!({ "code": wrong_code(&secret) })).await;
    assert_eq!((bad.status, bad.body["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("INVALID_CODE")));
    let ok = c.post("/two-factor/verify-totp", json!({ "code": code(&secret) })).await;
    assert_eq!(ok.body["user"]["twoFactorEnabled"], true);
    assert_eq!(c.get("/get-session").await.body["user"]["twoFactorEnabled"], true, "session rotated, still signed in");
    assert_eq!(c.post("/two-factor/enable", json!({ "password": "password123" })).await.body["code"], "TOTP_ALREADY_ENABLED");

    // A fresh sign-in now stops at the second factor.
    let mut d = c.fork();
    let res = d.post("/sign-in/email", json!({ "email": "ada@example.com", "password": "password123" })).await;
    assert_eq!(res.body, json!({ "twoFactorRedirect": true, "twoFactorMethods": ["totp"] }));
    assert!(!d.cookies.contains_key(SESSION));
    assert!(d.cookies.contains_key(TWO_FACTOR));
    assert_eq!(d.get("/get-session").await.body, Value::Null);
    assert_eq!(c.auth.db.list_sessions(ok.body["user"]["id"].as_str().unwrap()).await.unwrap().len(), 1, "no session leaked");

    let res = d.post("/two-factor/verify-totp", json!({ "code": code(&secret) })).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(res.body["token"].is_string());
    assert!(!d.cookies.contains_key(TWO_FACTOR));
    assert_eq!(d.get("/get-session").await.body["user"]["email"], "ada@example.com");

    // The challenge is single use.
    let mut e = c.fork();
    e.cookies.insert(TWO_FACTOR.into(), "forged".into());
    assert_eq!(e.post("/two-factor/verify-totp", json!({ "code": code(&secret) })).await.body["code"], "INVALID_TWO_FACTOR_COOKIE");

    // get-totp-uri returns the same secret.
    let res = c.post("/two-factor/get-totp-uri", json!({ "password": "password123" })).await;
    assert_eq!(secret_from_uri(res.body["totpURI"].as_str().unwrap()), secret);
}

#[tokio::test]
async fn username_sign_in_is_challenged_too() {
    let (mut c, secret, _) = user_with_totp(TwoFactorOptions::default(), "u@example.com").await;
    c.post("/update-user", json!({ "username": "uuu" })).await;
    let mut d = c.fork();
    let res = d.post("/sign-in/username", json!({ "username": "uuu", "password": "password123" })).await;
    assert_eq!(res.body["twoFactorRedirect"], true);
    assert_eq!(d.post("/two-factor/verify-totp", json!({ "code": code(&secret) })).await.status, StatusCode::OK);
}

#[tokio::test]
async fn backup_codes_are_single_use() {
    let (c, _, codes) = user_with_totp(TwoFactorOptions::default(), "b@example.com").await;
    let mut d = c.fork();
    sign_in(&mut d, "b@example.com").await;
    let res = d.post("/two-factor/verify-backup-code", json!({ "code": codes[0] })).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_eq!(d.get("/get-session").await.body["user"]["email"], "b@example.com");

    let mut e = c.fork();
    sign_in(&mut e, "b@example.com").await;
    let reuse = e.post("/two-factor/verify-backup-code", json!({ "code": codes[0] })).await;
    assert_eq!(reuse.body["code"], "INVALID_BACKUP_CODE");
    let user_id = d.get("/get-session").await.body["user"]["id"].as_str().unwrap().to_string();
    assert_eq!(two_factor::view_backup_codes(&c.auth, &user_id).await.unwrap().len(), 9);

    // Regenerating replaces every code.
    let mut c = c;
    let res = c.post("/two-factor/generate-backup-codes", json!({ "password": "password123" })).await;
    let fresh: Vec<String> = serde_json::from_value(res.body["backupCodes"].clone()).unwrap();
    assert_eq!(fresh.len(), 10);
    assert!(!fresh.contains(&codes[1]));
    assert_eq!(e.post("/two-factor/verify-backup-code", json!({ "code": codes[1] })).await.body["code"], "INVALID_BACKUP_CODE");
    assert_eq!(e.post("/two-factor/verify-backup-code", json!({ "code": fresh[0] })).await.status, StatusCode::OK);
}

#[tokio::test]
async fn trusted_device_skips_second_factor() {
    let (c, secret, _) = user_with_totp(TwoFactorOptions::default(), "t@example.com").await;
    let mut d = c.fork();
    sign_in(&mut d, "t@example.com").await;
    d.post("/two-factor/verify-totp", json!({ "code": code(&secret), "trustDevice": true })).await;
    let first_trust = d.cookies.get(TRUST).cloned().expect("trust cookie set");

    d.post("/sign-out", json!({})).await;
    let res = sign_in(&mut d, "t@example.com").await;
    assert!(res.get("twoFactorRedirect").is_none(), "{res}");
    assert!(res["token"].is_string());
    assert_ne!(d.cookies.get(TRUST), Some(&first_trust), "trust token rotates on use");

    // The old (rotated) trust cookie no longer works.
    let mut stale = c.fork();
    stale.cookies.insert(TRUST.into(), first_trust);
    assert_eq!(sign_in(&mut stale, "t@example.com").await["twoFactorRedirect"], true);
    assert!(!stale.cookies.contains_key(TRUST));

    // Disabling 2FA revokes the trusted device and turns the challenge off.
    assert_eq!(d.post("/two-factor/disable", json!({ "password": "wrong-pass" })).await.body["code"], "INVALID_PASSWORD");
    assert_eq!(d.post("/two-factor/disable", json!({ "password": "password123" })).await.body["status"], true);
    assert!(!d.cookies.contains_key(TRUST));
    assert_eq!(d.get("/get-session").await.body["user"]["twoFactorEnabled"], false);
    let mut e = c.fork();
    assert!(sign_in(&mut e, "t@example.com").await["token"].is_string());
}

#[tokio::test]
async fn attempts_per_challenge_are_limited() {
    let (c, secret, _) = user_with_totp(TwoFactorOptions::default(), "a@example.com").await;
    let mut d = c.fork();
    sign_in(&mut d, "a@example.com").await;
    for _ in 0..5 {
        assert_eq!(d.post("/two-factor/verify-totp", json!({ "code": wrong_code(&secret) })).await.body["code"], "INVALID_CODE");
    }
    let res = d.post("/two-factor/verify-totp", json!({ "code": code(&secret) })).await;
    assert_eq!(res.body["code"], "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE");
    let res = d.post("/two-factor/verify-totp", json!({ "code": code(&secret) })).await;
    assert_eq!(res.body["code"], "INVALID_TWO_FACTOR_COOKIE", "challenge was invalidated");
}

#[tokio::test]
async fn account_lockout_across_challenges() {
    let mut opts = TwoFactorOptions::default();
    opts.account_lockout.max_failed_attempts = 3;
    let (c, secret, _) = user_with_totp(opts, "l@example.com").await;
    for _ in 0..3 {
        let mut d = c.fork();
        sign_in(&mut d, "l@example.com").await;
        d.post("/two-factor/verify-totp", json!({ "code": wrong_code(&secret) })).await;
    }
    let mut d = c.fork();
    sign_in(&mut d, "l@example.com").await;
    let res = d.post("/two-factor/verify-totp", json!({ "code": code(&secret) })).await;
    assert_eq!((res.status, res.body["code"].as_str()), (StatusCode::TOO_MANY_REQUESTS, Some("ACCOUNT_TEMPORARILY_LOCKED")));
}

async fn otp_flow(storage: OtpStorage) {
    let outbox = Outbox::<TwoFactorOtp>::new();
    let mut opts = TwoFactorOptions::default();
    opts.otp.send_otp = Some(outbox.callback());
    opts.otp.storage = storage;
    let mut c = client_with(opts).await;
    c.sign_up("o@example.com", "password123").await;
    assert_eq!(c.post("/two-factor/enable", json!({ "password": "password123", "method": "otp" })).await.body["method"], "otp");
    assert_eq!(c.get("/get-session").await.body["user"]["twoFactorEnabled"], true);

    let mut d = c.fork();
    let res = sign_in(&mut d, "o@example.com").await;
    assert_eq!(res["twoFactorMethods"], json!(["otp"]));
    assert_eq!(d.post("/two-factor/verify-otp", json!({ "code": "123456" })).await.body["code"], "OTP_HAS_EXPIRED");
    assert_eq!(d.post("/two-factor/send-otp", json!({})).await.body["status"], true);
    let sent = outbox.last().unwrap();
    assert_eq!(sent.user.email, "o@example.com");
    assert_eq!(sent.otp.len(), 6);
    let wrong = if sent.otp == "000000" { "111111" } else { "000000" };
    assert_eq!(d.post("/two-factor/verify-otp", json!({ "code": wrong })).await.body["code"], "INVALID_CODE");
    let res = d.post("/two-factor/verify-otp", json!({ "code": sent.otp })).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_eq!(d.get("/get-session").await.body["user"]["email"], "o@example.com");
}

#[tokio::test]
async fn otp_plain() {
    otp_flow(OtpStorage::Plain).await;
}

#[tokio::test]
async fn otp_hashed_and_encrypted() {
    otp_flow(OtpStorage::Hashed).await;
    otp_flow(OtpStorage::Encrypted).await;
}

#[tokio::test]
async fn otp_not_configured() {
    let mut c = client_with(TwoFactorOptions::default()).await;
    c.sign_up("n@example.com", "password123").await;
    assert_eq!(c.post("/two-factor/enable", json!({ "password": "password123", "method": "otp" })).await.body["code"], "OTP_NOT_CONFIGURED");
    assert_eq!(c.post("/two-factor/send-otp", json!({})).await.body["code"], "OTP_NOT_CONFIGURED");
}

#[tokio::test]
async fn skip_verification_on_enable() {
    let opts = TwoFactorOptions { skip_verification_on_enable: true, ..Default::default() };
    let mut c = client_with(opts.clone()).await;
    let up = c.sign_up("s@example.com", "password123").await;
    c.post("/two-factor/enable", json!({ "password": "password123" })).await;
    assert_eq!(c.get("/get-session").await.body["user"]["twoFactorEnabled"], true);
    let user_id = up.body["user"]["id"].as_str().unwrap();
    let mut d = c.fork();
    assert_eq!(sign_in(&mut d, "s@example.com").await["twoFactorRedirect"], true);
    let current = two_factor::current_totp(&c.auth, &opts, user_id).await.unwrap();
    assert_eq!(d.post("/two-factor/verify-totp", json!({ "code": current })).await.status, StatusCode::OK);
}

#[tokio::test]
async fn remember_me_survives_the_challenge() {
    let (c, secret, _) = user_with_totp(TwoFactorOptions::default(), "r@example.com").await;
    let mut d = c.fork();
    d.post("/sign-in/email", json!({ "email": "r@example.com", "password": "password123", "rememberMe": false })).await;
    assert!(d.cookies.contains_key("ferroauth.dont_remember"));
    let res = d.post("/two-factor/verify-totp", json!({ "code": code(&secret) })).await;
    let session_cookie = res.headers.get_all("set-cookie").iter().map(|v| v.to_str().unwrap()).find(|c| c.starts_with(SESSION)).unwrap().to_string();
    assert!(!session_cookie.contains("Max-Age"), "browser-session cookie: {session_cookie}");
}

#[tokio::test]
async fn works_on_sqlite() {
    let db = ferroauth::db::SqlxAdapter::connect_with("sqlite::memory:", sqlx::any::AnyPoolOptions::new().max_connections(1)).await.unwrap();
    let auth = Auth::builder(base_options()).database(db).plugin(TwoFactor::new()).build().await.unwrap();
    let mut c = Client::new(auth);
    c.sign_up("q@example.com", "password123").await;
    let res = c.post("/two-factor/enable", json!({ "password": "password123" })).await;
    let secret = secret_from_uri(res.body["totpURI"].as_str().unwrap());
    let codes: Vec<String> = serde_json::from_value(res.body["backupCodes"].clone()).unwrap();
    c.post("/two-factor/verify-totp", json!({ "code": code(&secret) })).await;
    let mut d = c.fork();
    assert_eq!(sign_in(&mut d, "q@example.com").await["twoFactorRedirect"], true);
    d.post("/two-factor/verify-totp", json!({ "code": wrong_code(&secret) })).await;
    assert_eq!(d.post("/two-factor/verify-backup-code", json!({ "code": codes[3] })).await.status, StatusCode::OK);
    assert_eq!(d.get("/get-session").await.body["user"]["twoFactorEnabled"], true);
}
