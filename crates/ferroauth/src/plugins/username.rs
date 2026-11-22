//! Username plugin: adds `username` / `displayUsername` to users, accepts
//! `username` on sign-up and update-user, and adds `POST /sign-in/username`
//! and `POST /is-username-available`.

use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Extension, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::Plugin;
use crate::context::Auth;
use crate::db::{Adapter, DatabaseHooks, Record, Where};
use crate::error::{AuthError, Result};
use crate::models::from_record;
use crate::routes::email_password::{sign_in_with_password, SignInResponse};
use crate::schema::{Field, Schema, USER};
use crate::session::{ApiResponse, JsonBody, RequestMeta};

#[derive(Debug, Clone)]
pub struct UsernameOptions {
    pub min_length: usize,
    pub max_length: usize,
}

#[derive(Debug, Clone)]
pub struct Username {
    opts: Arc<UsernameOptions>,
}

impl Default for Username {
    fn default() -> Self {
        Self::new()
    }
}

impl Username {
    pub fn new() -> Self {
        Self { opts: Arc::new(UsernameOptions { min_length: 3, max_length: 30 }) }
    }

    pub fn with_options(opts: UsernameOptions) -> Self {
        Self { opts: Arc::new(opts) }
    }
}

fn err(code: &str, msg: &str) -> AuthError {
    AuthError::new(StatusCode::UNPROCESSABLE_ENTITY, code, msg)
}

fn validate(opts: &UsernameOptions, username: &str) -> Result<()> {
    let len = username.chars().count();
    if len < opts.min_length {
        return Err(err("USERNAME_TOO_SHORT", "Username is too short"));
    }
    if len > opts.max_length {
        return Err(err("USERNAME_TOO_LONG", "Username is too long"));
    }
    if !username.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.') {
        return Err(err("INVALID_USERNAME", "Username is invalid"));
    }
    Ok(())
}

struct Hooks(Arc<UsernameOptions>);

impl Hooks {
    async fn normalize(&self, db: &dyn Adapter, data: &mut Record, self_id: Option<&Value>) -> Result<()> {
        let Some(Value::String(raw)) = data.get("username").cloned() else { return Ok(()) };
        validate(&self.0, &raw)?;
        let normalized = raw.to_lowercase();
        if let Some(existing) = db.find_one(USER, &[Where::eq("username", normalized.clone())]).await? {
            if self_id.is_none_or(|id| existing.get("id") != Some(id)) {
                return Err(err("USERNAME_IS_ALREADY_TAKEN", "Username is already taken. Please try another."));
            }
        }
        if !matches!(data.get("displayUsername"), Some(Value::String(_))) {
            data.insert("displayUsername".into(), raw.into());
        }
        data.insert("username".into(), normalized.into());
        Ok(())
    }
}

#[async_trait]
impl DatabaseHooks for Hooks {
    async fn before_create(&self, db: &dyn Adapter, model: &str, data: &mut Record) -> Result<()> {
        if model == USER {
            self.normalize(db, data, None).await?;
        }
        Ok(())
    }

    async fn before_update(&self, db: &dyn Adapter, model: &str, filter: &[Where], data: &mut Record) -> Result<()> {
        if model == USER {
            let id = filter.iter().find(|w| w.field == "id").map(|w| &w.value);
            self.normalize(db, data, id).await?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInUsername {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub remember_me: Option<bool>,
    #[serde(default, rename = "callbackURL")]
    pub callback_url: Option<String>,
}

pub async fn sign_in_username(auth: &Auth, meta: &RequestMeta, body: SignInUsername) -> Result<ApiResponse<SignInResponse>> {
    auth.validate_redirect(body.callback_url.as_deref())?;
    let rec = auth.raw_adapter().find_one(USER, &[Where::eq("username", body.username.trim().to_lowercase())]).await?;
    let user = rec.map(from_record).transpose()?;
    sign_in_with_password(auth, meta, user, &body.password, body.remember_me, body.callback_url).await.map_err(|e| {
        if e.code == "INVALID_EMAIL_OR_PASSWORD" {
            AuthError::new(StatusCode::UNAUTHORIZED, "INVALID_USERNAME_OR_PASSWORD", "Invalid username or password")
        } else {
            e
        }
    })
}

#[derive(Debug, Deserialize)]
pub struct IsUsernameAvailable {
    pub username: String,
}

#[derive(Debug, Serialize)]
pub struct Available {
    pub available: bool,
}

#[async_trait]
impl Plugin for Username {
    fn id(&self) -> &'static str {
        "username"
    }

    fn schema(&self) -> Schema {
        Schema::extend_table(
            USER,
            vec![Field::string("username").optional().unique().input(), Field::string("displayUsername").optional().input()],
        )
    }

    fn database_hooks(&self) -> Option<Arc<dyn DatabaseHooks>> {
        Some(Arc::new(Hooks(self.opts.clone())))
    }

    fn routes(&self) -> Option<Router<Auth>> {
        Some(
            Router::new()
                .route(
                    "/sign-in/username",
                    post(|State(a): State<Auth>, m: RequestMeta, JsonBody(b): JsonBody<SignInUsername>| async move {
                        sign_in_username(&a, &m, b).await
                    }),
                )
                .route(
                    "/is-username-available",
                    post(
                        |State(a): State<Auth>,
                         Extension(opts): Extension<Arc<UsernameOptions>>,
                         JsonBody(b): JsonBody<IsUsernameAvailable>| async move {
                            validate(&opts, &b.username)?;
                            let taken =
                                a.raw_adapter().find_one(USER, &[Where::eq("username", b.username.to_lowercase())]).await?.is_some();
                            Ok::<_, AuthError>(ApiResponse::ok(Available { available: !taken }))
                        },
                    ),
                )
                .layer(Extension(self.opts.clone())),
        )
    }
}
