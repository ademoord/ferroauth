//! Linked accounts: `GET /list-accounts`, `POST /unlink-account`.

use serde::{Deserialize, Serialize};

use super::session::Status;
use crate::context::Auth;
use crate::error::{AuthError, Result};
use crate::models::{ts, Timestamp};
use crate::session::{require_session, ApiResponse, RequestMeta};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfo {
    pub id: String,
    pub provider_id: String,
    pub account_id: String,
    pub user_id: String,
    pub scopes: Vec<String>,
    #[serde(with = "ts")]
    pub created_at: Timestamp,
    #[serde(with = "ts")]
    pub updated_at: Timestamp,
}

pub async fn list_accounts(auth: &Auth, meta: &RequestMeta) -> Result<ApiResponse<Vec<AccountInfo>>> {
    let current = require_session(auth, &meta.headers).await?;
    let accounts = auth.db.find_accounts(&current.user.id).await?;
    Ok(ApiResponse::ok(
        accounts
            .into_iter()
            .map(|a| AccountInfo {
                scopes: a.scope.as_deref().map(|s| s.split([',', ' ']).filter(|s| !s.is_empty()).map(String::from).collect()).unwrap_or_default(),
                id: a.id,
                provider_id: a.provider_id,
                account_id: a.account_id,
                user_id: a.user_id,
                created_at: a.created_at,
                updated_at: a.updated_at,
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlinkAccount {
    pub provider_id: String,
    #[serde(default)]
    pub account_id: Option<String>,
}

pub async fn unlink_account(auth: &Auth, meta: &RequestMeta, body: UnlinkAccount) -> Result<ApiResponse<Status>> {
    let current = require_session(auth, &meta.headers).await?;
    let accounts = auth.db.find_accounts(&current.user.id).await?;
    if accounts.len() <= 1 {
        return Err(AuthError::failed_to_unlink_last_account());
    }
    let target = accounts
        .iter()
        .find(|a| a.provider_id == body.provider_id && body.account_id.as_ref().is_none_or(|id| *id == a.account_id))
        .ok_or_else(AuthError::account_not_found)?;
    auth.db.delete_account(&target.id).await?;
    Ok(Status::ok())
}
