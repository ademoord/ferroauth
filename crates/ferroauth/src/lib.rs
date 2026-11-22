//! # ferroauth
//!
//! A comprehensive, batteries-included authentication framework for [Axum]:
//! email & password, sessions, OAuth social sign-in, email verification,
//! password reset, and plugins (username, bearer tokens, magic links,
//! two-factor authentication), on SQLite, Postgres, MySQL or your own storage.
//!
//! ```no_run
//! use ferroauth::{Auth, AuthOptions, EmailAndPasswordOptions, AuthSession};
//! use axum::{routing::get, Router};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let auth = Auth::builder(AuthOptions {
//!     base_url: "http://localhost:3000".into(),
//!     secret: Some("a-long-random-secret-at-least-32-chars".into()),
//!     email_and_password: EmailAndPasswordOptions { enabled: true, ..Default::default() },
//!     ..Default::default()
//! })
//! .database(ferroauth::db::SqlxAdapter::connect("sqlite://auth.db?mode=rwc").await?)
//! .build()
//! .await?;
//!
//! let app = Router::new()
//!     .route("/me", get(|s: AuthSession| async move { s.user.email }))
//!     .merge(auth.router())
//!     .layer(auth.layer());
//! # Ok(()) }
//! ```
//!
//! [Axum]: https://github.com/tokio-rs/axum

#![forbid(unsafe_code)]

pub mod context;
pub mod cookies;
pub mod crypto;
pub mod db;
pub mod error;
pub mod extract;
pub mod models;
#[cfg(feature = "oauth")]
pub mod oauth;
pub mod options;
pub mod plugins;
mod rate_limit;
pub mod routes;
pub mod schema;
pub mod session;

pub use context::{Auth, AuthBuilder, AuthContext};
pub use error::{AuthError, Result};
pub use extract::{AuthSession, MaybeAuthSession};
pub use models::{Account, Session, SessionWithUser, User, Verification};
pub use options::*;
pub use session::{ApiResponse, RequestMeta};
