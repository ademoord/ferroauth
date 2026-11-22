//! Axum extractors for your own routes. Requires `.layer(auth.layer())`.
//!
//! ```ignore
//! async fn me(AuthSession { user, .. }: AuthSession) -> String { user.email }
//! ```

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::context::Auth;
use crate::error::{AuthError, Result};
use crate::models::{Session, User};

fn auth_from(parts: &Parts) -> Result<Auth> {
    parts
        .extensions
        .get::<Auth>()
        .cloned()
        .ok_or_else(|| AuthError::internal("Auth extension missing: add `.layer(auth.layer())` to your router"))
}

/// The authenticated session; rejects with 401 when there is none.
#[derive(Debug, Clone)]
pub struct AuthSession {
    pub session: Session,
    pub user: User,
}

impl<S: Send + Sync> FromRequestParts<S> for AuthSession {
    type Rejection = AuthError;
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self> {
        let auth = auth_from(parts)?;
        let s = auth.get_session(&parts.headers).await?.ok_or_else(AuthError::unauthorized)?;
        Ok(AuthSession { session: s.session, user: s.user })
    }
}

/// The session if there is one.
#[derive(Debug, Clone)]
pub struct MaybeAuthSession(pub Option<AuthSession>);

impl<S: Send + Sync> FromRequestParts<S> for MaybeAuthSession {
    type Rejection = AuthError;
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self> {
        let auth = auth_from(parts)?;
        let s = auth.get_session(&parts.headers).await?;
        Ok(MaybeAuthSession(s.map(|s| AuthSession { session: s.session, user: s.user })))
    }
}
