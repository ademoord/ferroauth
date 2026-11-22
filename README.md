<p align="center">
  <img src="assets/logo.svg" alt="ferroauth logo: an iron shield with a molten keyhole" width="180">
</p>

<h1 align="center">ferroauth</h1>

<p align="center">
  <b>Forged in iron. Tempered in Rust.</b><br>
  <i>Your auth: secured, streamlined, and yours.</i>
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-f97316"></a>
  <img alt="Built with Rust" src="https://img.shields.io/badge/built%20with-Rust-b7410e?logo=rust">
  <img alt="Axum 0.8" src="https://img.shields.io/badge/axum-0.8-374151">
  <img alt="unsafe: forbidden" src="https://img.shields.io/badge/unsafe-forbidden-16a34a">
</p>

---

> *Iron does not ask permission to be strong.*
> *It is heated, hammered and folded until strength is simply what it is.*

Authentication is the gate to everything you build. It deserves the same treatment.
**ferroauth** is an immersive auth for your app, built with the magnificent Rust: a
complete, batteries-included authentication framework for [Axum](https://github.com/tokio-rs/axum).
One builder call gives your app sign-up, sessions, social login and two-factor authentication,
with the security decisions already made, so you can get back to building the thing you came here to build.

```rust
let auth = Auth::builder(options).database(db).plugin(TwoFactor::new()).build().await?;
let app  = Router::new().merge(auth.router()).layer(auth.layer());
```

That's the whole integration.

## ✨ What's in the forge

| | |
|---|---|
| 🔑 **Email & password** | Sign-up, sign-in, change password, reset by email, email verification, change email, delete account |
| 🍪 **Sessions** | Signed `HttpOnly` cookies, sliding expiry, "remember me", list and revoke sessions on every device |
| 🌐 **Social sign-in** | GitHub, Google, Discord, or any OIDC provider (Keycloak, Auth0, Okta…), with account linking |
| 🛡️ **Two-factor** | Authenticator apps (TOTP), email/SMS codes, backup codes, "trust this device", lockout |
| ✉️ **Magic links** | Passwordless sign-in by email |
| 👤 **Usernames** | Sign in with a username instead of an email |
| 📱 **Bearer tokens** | `Authorization: Bearer` for mobile apps and API clients |
| 🗄️ **Any database** | SQLite, Postgres and MySQL built in, with auto-migration; or implement one small trait |
| 🧩 **Plugins** | Add tables, endpoints and hooks without forking |

## 🔥 Quick start

```toml
[dependencies]
ferroauth = { git = "https://github.com/ademoord/ferroauth" }
axum = "0.8"
tokio = { version = "1", features = ["full"] }
```

```rust
use axum::{routing::get, Router};
use ferroauth::{db::SqlxAdapter, Auth, AuthOptions, AuthSession, EmailAndPasswordOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Auth::builder(AuthOptions {
        base_url: "http://localhost:3000".into(),
        secret: Some(std::env::var("FERROAUTH_SECRET")?), // 32+ random characters
        email_and_password: EmailAndPasswordOptions { enabled: true, ..Default::default() },
        ..Default::default()
    })
    .database(SqlxAdapter::connect("sqlite://auth.db?mode=rwc").await?) // tables are created for you
    .build()
    .await?;

    let app = Router::new()
        .route("/me", get(|s: AuthSession| async move { format!("Hello, {}!", s.user.name) }))
        .merge(auth.router()) // mounts /api/auth/*
        .layer(auth.layer()); // powers the AuthSession extractor

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await?;
    Ok(())
}
```

From the browser it's plain JSON, and the session rides in a secure cookie:

```ts
await fetch("/api/auth/sign-up/email", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ name: "Ada", email: "ada@example.com", password: "correct horse battery" }),
});

const me = await fetch("/me").then((r) => r.text()); // "Hello, Ada!"
```

Want to see it run first? There's a demo app with every plugin switched on:

```sh
git clone https://github.com/ademoord/ferroauth && cd ferroauth
cargo run --example basic   # then open http://localhost:3000
```

## 🛡️ Guarding your routes

Two extractors, nothing to wire by hand:

```rust
use ferroauth::{AuthSession, MaybeAuthSession};

// 401 unless signed in
async fn dashboard(AuthSession { user, session }: AuthSession) -> String {
    format!("{} (session expires {})", user.email, session.expires_at)
}

// works for everyone, knows who's who
async fn home(MaybeAuthSession(s): MaybeAuthSession) -> String {
    match s {
        Some(s) => format!("Welcome back, {}", s.user.name),
        None => "Hello, stranger".into(),
    }
}
```

## 🧩 Plugins

```rust
use ferroauth::oauth::providers::github;
use ferroauth::plugins::{Bearer, MagicLink, MagicLinkEmail, TwoFactor, Username};
use ferroauth::Callback;

let auth = Auth::builder(options)
    .database(db)
    .social_provider(github(client_id, client_secret))
    .plugin(Username::new())
    .plugin(Bearer::new())
    .plugin(TwoFactor::new())
    .plugin(MagicLink::new(Callback::new(|mail: MagicLinkEmail| async move {
        send_email(&mail.email, &mail.url).await; // your mailer
    })))
    .build()
    .await?;
```

### Two-factor authentication

Turning it on is one call. After that, users:

1. Call `POST /two-factor/enable` with their password. They get an `otpauth://` URI (show it as a QR code) and 10 backup codes.
2. Confirm with a code from their authenticator app at `POST /two-factor/verify-totp`. 2FA is now on.
3. From then on, signing in answers `{ "twoFactorRedirect": true, "twoFactorMethods": ["totp"] }` instead of a session.
   Show your code screen, and the session is created once a code checks out.

Brute force is not invited:
- 5 attempts per sign-in challenge.
- The account locks for 15 minutes after 10 consecutive failures.
- Secrets and backup codes are encrypted at rest with XChaCha20-Poly1305.
- "Trust this device" tokens are stored server-side, rotate on every use and can be revoked.

### Write your own

A plugin is one trait. It can bring its own tables and columns, endpoints, database hooks,
request/response hooks, token resolution and rate-limit rules:

```rust
#[async_trait]
impl Plugin for AuditLog {
    fn id(&self) -> &'static str { "audit-log" }

    fn schema(&self) -> Schema {
        Schema::new(vec![Table::new("auditEvent", vec![
            Field::string("userId"), Field::string("action"), Field::date("at"),
        ])])
    }

    fn database_hooks(&self) -> Option<Arc<dyn DatabaseHooks>> {
        Some(Arc::new(RecordSignIns)) // e.g. write an auditEvent whenever a session is created
    }
}
```

## 🔒 Security, by default

None of this is opt-in. You'd have to go out of your way to turn it off.

| Threat | What ferroauth does |
|---|---|
| Stolen or forged cookies | HMAC-signed, `HttpOnly`, `SameSite=Lax`; `Secure` and `__Secure-` prefixed on https |
| CSRF | State-changing requests must come from a trusted origin (wildcards like `https://*.example.com` supported) |
| Open redirects | Every `callbackURL` / `redirectTo` is checked against trusted origins |
| Credential stuffing | Per-IP rate limits, stricter on sign-in, sign-up and recovery flows |
| Password database leaks | scrypt with per-password salts and NFKC-normalised input |
| Account probing | Sign-in and password reset give the same answer, in the same time, whether or not the account exists |
| OAuth hijacking | PKCE (S256), plus state that is stored server-side *and* bound to the browser |
| Session theft | Sliding expiry, per-device revocation, a fresh session required to delete an account |

Found something we missed? Please report it privately through the repository's **Security** tab rather than in a public issue.

## 🗄️ Bring your database

| | |
|---|---|
| `SqlxAdapter` | SQLite, Postgres and MySQL. Creates missing tables and columns on startup; `auth.generate_schema_sql()` prints the DDL if you'd rather migrate yourself. |
| `MemoryAdapter` | For tests and prototypes. |
| Your own | Implement the 8-method `Adapter` trait (`create`, `find_one`, `find_many`, `update`, `update_many`, `delete`, `delete_many`, `count`). It works on generic records, so plugins with their own tables just work. |

## 🏗️ Under the hood

```
crates/ferroauth/src
├── context.rs     Auth: the instance, its builder, origin & redirect checks
├── options.rs     every knob, with sensible defaults
├── schema.rs      declarative schema: core tables + plugin fields
├── db/            Adapter trait, SQL & memory adapters, typed operations + hooks
├── crypto.rs      scrypt, HMAC, JWT, PKCE, TOTP/HOTP, XChaCha20-Poly1305
├── session.rs     session lookup, refresh and creation
├── extract.rs     AuthSession / MaybeAuthSession
├── routes/        the HTTP endpoints + CSRF, rate-limit and plugin middleware
├── oauth/         provider trait, generic OAuth2/OIDC, presets
└── plugins/       username, bearer, magic_link, two_factor
```

Every endpoint is also a plain `async fn(&Auth, …)`, so your server code can call it directly:
no HTTP round-trip, no duplicated logic.

## 🗺️ Roadmap

- [x] Email & password, sessions, email verification, password reset
- [x] OAuth 2.0 / OIDC social sign-in with account linking
- [x] Username, bearer and magic-link plugins
- [x] Two-factor authentication (TOTP, OTP, backup codes, trusted devices)
- [ ] Passkeys (WebAuthn)
- [ ] Organizations, teams & roles
- [ ] Admin plugin (ban, impersonate, manage users)
- [ ] JWT / JWKS for service-to-service auth
- [ ] API keys
- [ ] Redis session storage
- [ ] OAuth token refresh
- [ ] Publish to crates.io

## 🤝 Contributing

Every blacksmith started by fetching water. Issues, ideas, docs fixes and new plugins are all welcome.

```sh
cargo test                  # unit, HTTP, OAuth, SQLite and two-factor suites
cargo clippy --all-targets  # keep it warning-free
```

The unchecked roadmap items are a good place to start. For larger changes, please open an issue first so we can shape them together.

## 📜 License

[MIT](LICENSE). Take it, shape it, make it yours.

<p align="center"><sub>Made with 🔥 and 🦀. Keep your gates strong.</sub></p>
