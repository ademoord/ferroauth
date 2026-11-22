//! Plugin system. A plugin can add schema, endpoints, database hooks, request /
//! response hooks, session-token resolution and rate-limit rules.

pub mod bearer;
pub mod magic_link;
pub mod two_factor;
pub mod username;

use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::Request;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Router;

use crate::context::Auth;
use crate::db::DatabaseHooks;
use crate::options::RateLimitRule;
use crate::schema::Schema;

pub use bearer::Bearer;
pub use magic_link::{MagicLink, MagicLinkEmail};
pub use two_factor::{TwoFactor, TwoFactorOptions, TwoFactorOtp};
pub use username::Username;

/// The request an [`Plugin::on_response`] hook is responding to.
#[derive(Debug, Clone)]
pub struct RequestInfo {
    /// Path relative to the auth base path, e.g. `/sign-in/email`.
    pub path: String,
    pub headers: HeaderMap,
}

#[async_trait]
pub trait Plugin: Send + Sync + 'static {
    fn id(&self) -> &'static str;

    /// Tables / fields this plugin needs. Merged into the core schema.
    fn schema(&self) -> Schema {
        Schema::default()
    }

    /// Extra endpoints, relative to the auth base path.
    fn routes(&self) -> Option<Router<Auth>> {
        None
    }

    fn database_hooks(&self) -> Option<Arc<dyn DatabaseHooks>> {
        None
    }

    fn rate_limit_rules(&self) -> Vec<RateLimitRule> {
        Vec::new()
    }

    /// Provide a session token when there is no session cookie (e.g. from an
    /// `Authorization` header). Return the raw (unsigned) token.
    async fn resolve_session_token(&self, _auth: &Auth, _headers: &HeaderMap) -> Option<String> {
        None
    }

    /// Runs before every auth endpoint. Return `Err(response)` to short-circuit.
    async fn on_request(&self, _auth: &Auth, req: Request) -> Result<Request, Response> {
        Ok(req)
    }

    /// Runs after every auth endpoint; may rewrite the response.
    async fn on_response(&self, _auth: &Auth, _req: &RequestInfo, res: Response) -> Response {
        res
    }
}
