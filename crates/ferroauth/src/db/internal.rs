//! Typed operations over the generic adapter,
//! running database hooks around writes.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use serde_json::Value;

use super::{Adapter, FindMany, Record, SortDirection, Where};
use crate::crypto::generate_id;
use crate::error::{AuthError, Result};
use crate::models::{from_record, ts_value, Account, Session, Timestamp, User, Verification};
use crate::schema::{Schema, ACCOUNT, SESSION, USER, VERIFICATION};

/// Lifecycle hooks around writes.
/// Returning an error from a `before_*` hook aborts the operation.
#[async_trait]
pub trait DatabaseHooks: Send + Sync + 'static {
    async fn before_create(&self, _db: &dyn Adapter, _model: &str, _data: &mut Record) -> Result<()> {
        Ok(())
    }
    async fn after_create(&self, _db: &dyn Adapter, _model: &str, _record: &Record) {}
    async fn before_update(&self, _db: &dyn Adapter, _model: &str, _filter: &[Where], _data: &mut Record) -> Result<()> {
        Ok(())
    }
    async fn after_update(&self, _db: &dyn Adapter, _model: &str, _record: &Record) {}
    async fn before_delete(&self, _db: &dyn Adapter, _model: &str, _record: &Record) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct InternalAdapter {
    db: Arc<dyn Adapter>,
    hooks: Arc<Vec<Arc<dyn DatabaseHooks>>>,
    schema: Arc<Schema>,
}

fn now() -> Value {
    ts_value(&Utc::now())
}

impl InternalAdapter {
    pub(crate) fn new(db: Arc<dyn Adapter>, hooks: Vec<Arc<dyn DatabaseHooks>>, schema: Schema) -> Self {
        Self { db, hooks: Arc::new(hooks), schema: Arc::new(schema) }
    }

    /// The raw generic adapter (for plugin tables).
    pub fn adapter(&self) -> &dyn Adapter {
        self.db.as_ref()
    }

    // ---- generic, hook-aware primitives -------------------------------------------

    pub async fn create(&self, model: &str, mut data: Record) -> Result<Record> {
        data.entry("id").or_insert_with(|| Value::String(generate_id()));
        if let Some(table) = self.schema.table(model) {
            for f in &table.fields {
                if let Some(default) = &f.default_value {
                    data.entry(f.name.clone()).or_insert_with(|| default.clone());
                }
            }
        }
        for h in self.hooks.iter() {
            h.before_create(self.adapter(), model, &mut data).await?;
        }
        let rec = self.db.create(model, data).await?;
        for h in self.hooks.iter() {
            h.after_create(self.adapter(), model, &rec).await;
        }
        Ok(rec)
    }

    pub async fn update(&self, model: &str, filter: &[Where], mut data: Record) -> Result<Option<Record>> {
        for h in self.hooks.iter() {
            h.before_update(self.adapter(), model, filter, &mut data).await?;
        }
        let rec = self.db.update(model, filter, data).await?;
        if let Some(rec) = &rec {
            for h in self.hooks.iter() {
                h.after_update(self.adapter(), model, rec).await;
            }
        }
        Ok(rec)
    }

    async fn delete_checked(&self, model: &str, filter: &[Where]) -> Result<()> {
        if !self.hooks.is_empty() {
            for rec in self.db.find_many(model, filter, FindMany::default()).await? {
                for h in self.hooks.iter() {
                    h.before_delete(self.adapter(), model, &rec).await?;
                }
            }
        }
        self.db.delete_many(model, filter).await?;
        Ok(())
    }

    // ---- users ---------------------------------------------------------------------

    /// Create a user. `data` must contain at least `name` and `email`; plugin /
    /// additional fields may be included.
    pub async fn create_user(&self, mut data: Record) -> Result<User> {
        if let Some(Value::String(email)) = data.get_mut("email") {
            *email = email.to_lowercase();
        }
        data.entry("emailVerified").or_insert(Value::Bool(false));
        data.entry("image").or_insert(Value::Null);
        data.insert("createdAt".into(), now());
        data.insert("updatedAt".into(), now());
        from_record(self.create(USER, data).await?)
    }

    pub async fn find_user_by_id(&self, id: &str) -> Result<Option<User>> {
        self.db.find_one(USER, &[Where::eq("id", id)]).await?.map(from_record).transpose()
    }

    pub async fn find_user_by_email(&self, email: &str) -> Result<Option<User>> {
        self.db.find_one(USER, &[Where::eq("email", email.to_lowercase())]).await?.map(from_record).transpose()
    }

    pub async fn update_user(&self, id: &str, mut data: Record) -> Result<User> {
        if let Some(Value::String(email)) = data.get_mut("email") {
            *email = email.to_lowercase();
        }
        data.insert("updatedAt".into(), now());
        let rec = self.update(USER, &[Where::eq("id", id)], data).await?.ok_or_else(AuthError::user_not_found)?;
        from_record(rec)
    }

    /// Delete a user together with their sessions and accounts.
    pub async fn delete_user(&self, id: &str) -> Result<()> {
        self.delete_checked(USER, &[Where::eq("id", id)]).await?;
        self.db.delete_many(SESSION, &[Where::eq("userId", id)]).await?;
        self.db.delete_many(ACCOUNT, &[Where::eq("userId", id)]).await?;
        Ok(())
    }

    pub async fn list_users(&self, limit: Option<usize>, offset: Option<usize>) -> Result<Vec<User>> {
        let opts = FindMany { limit, offset, sort_by: Some(("createdAt".into(), SortDirection::Asc)) };
        self.db.find_many(USER, &[], opts).await?.into_iter().map(from_record).collect()
    }

    // ---- sessions ------------------------------------------------------------------

    pub async fn create_session(
        &self,
        user_id: &str,
        token: String,
        expires_at: Timestamp,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<Session> {
        let mut data = Record::new();
        data.insert("token".into(), token.into());
        data.insert("userId".into(), user_id.into());
        data.insert("expiresAt".into(), ts_value(&expires_at));
        data.insert("ipAddress".into(), ip_address.map(Value::String).unwrap_or(Value::Null));
        data.insert("userAgent".into(), user_agent.map(Value::String).unwrap_or(Value::Null));
        data.insert("createdAt".into(), now());
        data.insert("updatedAt".into(), now());
        from_record(self.create(SESSION, data).await.map_err(|e| {
            tracing::error!(error = %e, "failed to create session");
            AuthError::failed_to_create_session()
        })?)
    }

    pub async fn find_session(&self, token: &str) -> Result<Option<(Session, User)>> {
        let Some(session) = self.db.find_one(SESSION, &[Where::eq("token", token)]).await? else { return Ok(None) };
        let session: Session = from_record(session)?;
        let Some(user) = self.find_user_by_id(&session.user_id).await? else { return Ok(None) };
        Ok(Some((session, user)))
    }

    pub async fn update_session(&self, token: &str, mut data: Record) -> Result<Option<Session>> {
        data.insert("updatedAt".into(), now());
        self.update(SESSION, &[Where::eq("token", token)], data).await?.map(from_record).transpose()
    }

    pub async fn list_sessions(&self, user_id: &str) -> Result<Vec<Session>> {
        let opts = FindMany { sort_by: Some(("createdAt".into(), SortDirection::Asc)), ..Default::default() };
        self.db.find_many(SESSION, &[Where::eq("userId", user_id)], opts).await?.into_iter().map(from_record).collect()
    }

    pub async fn delete_session(&self, token: &str) -> Result<()> {
        self.delete_checked(SESSION, &[Where::eq("token", token)]).await
    }

    pub async fn delete_user_sessions(&self, user_id: &str) -> Result<()> {
        self.delete_checked(SESSION, &[Where::eq("userId", user_id)]).await
    }

    pub async fn delete_other_sessions(&self, user_id: &str, keep_token: &str) -> Result<()> {
        self.delete_checked(SESSION, &[Where::eq("userId", user_id), Where::ne("token", keep_token)]).await
    }

    // ---- accounts ------------------------------------------------------------------

    pub async fn create_account(&self, mut data: Record) -> Result<Account> {
        data.insert("createdAt".into(), now());
        data.insert("updatedAt".into(), now());
        from_record(self.create(ACCOUNT, data).await?)
    }

    pub async fn create_credential_account(&self, user_id: &str, password_hash: &str) -> Result<Account> {
        let mut data = Record::new();
        data.insert("accountId".into(), user_id.into());
        data.insert("providerId".into(), "credential".into());
        data.insert("userId".into(), user_id.into());
        data.insert("password".into(), password_hash.into());
        self.create_account(data).await
    }

    pub async fn find_accounts(&self, user_id: &str) -> Result<Vec<Account>> {
        self.db.find_many(ACCOUNT, &[Where::eq("userId", user_id)], FindMany::default()).await?.into_iter().map(from_record).collect()
    }

    pub async fn find_account(&self, account_id: &str, provider_id: &str) -> Result<Option<Account>> {
        self.db
            .find_one(ACCOUNT, &[Where::eq("accountId", account_id), Where::eq("providerId", provider_id)])
            .await?
            .map(from_record)
            .transpose()
    }

    pub async fn find_credential_account(&self, user_id: &str) -> Result<Option<Account>> {
        self.db
            .find_one(ACCOUNT, &[Where::eq("userId", user_id), Where::eq("providerId", "credential")])
            .await?
            .map(from_record)
            .transpose()
    }

    pub async fn update_account(&self, id: &str, mut data: Record) -> Result<Option<Account>> {
        data.insert("updatedAt".into(), now());
        self.update(ACCOUNT, &[Where::eq("id", id)], data).await?.map(from_record).transpose()
    }

    pub async fn update_password(&self, user_id: &str, password_hash: &str) -> Result<()> {
        let mut data = Record::new();
        data.insert("password".into(), password_hash.into());
        data.insert("updatedAt".into(), now());
        self.update(ACCOUNT, &[Where::eq("userId", user_id), Where::eq("providerId", "credential")], data).await?;
        Ok(())
    }

    pub async fn delete_account(&self, id: &str) -> Result<()> {
        self.delete_checked(ACCOUNT, &[Where::eq("id", id)]).await
    }

    // ---- verification values -------------------------------------------------------

    pub async fn create_verification(&self, identifier: &str, value: &str, expires_at: Timestamp) -> Result<Verification> {
        let mut data = Record::new();
        data.insert("identifier".into(), identifier.into());
        data.insert("value".into(), value.into());
        data.insert("expiresAt".into(), ts_value(&expires_at));
        data.insert("createdAt".into(), now());
        data.insert("updatedAt".into(), now());
        from_record(self.create(VERIFICATION, data).await?)
    }

    /// Latest verification value for `identifier` (expired values are returned too; check `expires_at`).
    pub async fn find_verification(&self, identifier: &str) -> Result<Option<Verification>> {
        let opts = FindMany { limit: Some(1), sort_by: Some(("createdAt".into(), SortDirection::Desc)), ..Default::default() };
        let rows = self.db.find_many(VERIFICATION, &[Where::eq("identifier", identifier)], opts).await?;
        rows.into_iter().next().map(from_record).transpose()
    }

    /// Find and delete the latest value for `identifier`. Returns `None` if
    /// there was none or another request consumed it first (single use).
    pub async fn consume_verification(&self, identifier: &str) -> Result<Option<Verification>> {
        let Some(v) = self.find_verification(identifier).await? else { return Ok(None) };
        let deleted = self.db.delete_many(VERIFICATION, &[Where::eq("id", v.id.clone())]).await?;
        Ok((deleted > 0).then_some(v))
    }

    pub async fn delete_verification(&self, id: &str) -> Result<()> {
        self.db.delete_many(VERIFICATION, &[Where::eq("id", id)]).await?;
        Ok(())
    }

    pub async fn delete_verifications_by_identifier(&self, identifier: &str) -> Result<()> {
        self.db.delete_many(VERIFICATION, &[Where::eq("identifier", identifier)]).await?;
        Ok(())
    }

    /// Remove expired sessions and verification values.
    pub async fn purge_expired(&self) -> Result<u64> {
        let now = now();
        let a = self.db.delete_many(SESSION, &[Where::lt("expiresAt", now.clone())]).await?;
        let b = self.db.delete_many(VERIFICATION, &[Where::lt("expiresAt", now)]).await?;
        Ok(a + b)
    }
}
