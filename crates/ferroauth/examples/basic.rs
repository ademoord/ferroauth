//! Example app: `cargo run --example basic`, then open http://localhost:3000
//!
//! Env: DATABASE_URL (default sqlite://ferroauth-demo.db?mode=rwc), FERROAUTH_SECRET,
//! GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET (optional).

use axum::response::Html;
use axum::routing::get;
use axum::{Json, Router};
use ferroauth::db::SqlxAdapter;
use ferroauth::plugins::{Bearer, MagicLink, MagicLinkEmail, TwoFactor, TwoFactorOptions, TwoFactorOtp, Username};
use ferroauth::{Auth, AuthOptions, AuthSession, Callback, EmailAndPasswordOptions, EmailVerificationOptions, MaybeAuthSession};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info,ferroauth=debug".into())).init();

    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(3000);
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://ferroauth-demo.db?mode=rwc".into());

    let options = AuthOptions {
        app_name: "ferroauth demo".into(),
        base_url: format!("http://localhost:{port}"),
        email_and_password: EmailAndPasswordOptions {
            enabled: true,
            send_reset_password: Some(Callback::new(|mail: ferroauth::ResetPasswordEmail| async move {
                tracing::info!(to = %mail.user.email, url = %mail.url, "📧 reset password email");
            })),
            ..Default::default()
        },
        email_verification: EmailVerificationOptions {
            send_verification_email: Some(Callback::new(|mail: ferroauth::VerificationEmail| async move {
                tracing::info!(to = %mail.user.email, url = %mail.url, "📧 verification email");
            })),
            send_on_sign_up: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let mut builder = Auth::builder(options)
        .database(SqlxAdapter::connect(&db_url).await?)
        .plugin(Username::new())
        .plugin(Bearer::new())
        .plugin(TwoFactor::with_options(TwoFactorOptions {
            issuer: Some("ferroauth demo".into()),
            otp: ferroauth::plugins::two_factor::OtpOptions {
                send_otp: Some(Callback::new(|m: TwoFactorOtp| async move {
                    tracing::info!(to = %m.user.email, code = %m.otp, "📧 two-factor code");
                })),
                ..Default::default()
            },
            ..Default::default()
        }))
        .plugin(MagicLink::new(Callback::new(|mail: MagicLinkEmail| async move {
            tracing::info!(to = %mail.email, url = %mail.url, "📧 magic link");
        })));
    if let (Ok(id), Ok(secret)) = (std::env::var("GITHUB_CLIENT_ID"), std::env::var("GITHUB_CLIENT_SECRET")) {
        builder = builder.social_provider(ferroauth::oauth::providers::github(id, secret));
    }
    let auth = builder.build().await?;

    let app = Router::new()
        .route("/", get(|| async { Html(include_str!("index.html")) }))
        .route("/api/me", get(|s: AuthSession| async move { Json(json!({ "user": s.user, "session": s.session })) }))
        .route(
            "/api/hello",
            get(|MaybeAuthSession(s): MaybeAuthSession| async move {
                match s {
                    Some(s) => format!("Hello, {}!", s.user.name),
                    None => "Hello, stranger!".to_string(),
                }
            }),
        )
        .merge(auth.router())
        .layer(auth.layer());

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    tracing::info!("listening on http://localhost:{port}");
    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await?;
    Ok(())
}
