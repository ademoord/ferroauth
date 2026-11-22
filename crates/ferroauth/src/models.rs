//! Core models. Serialised with camelCase keys, the same JSON shape
//! clients receive. Fields added by plugins or `additional_fields` land in
//! `extra`.

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

use crate::db::Record;
use crate::error::AuthError;

pub type Timestamp = DateTime<Utc>;

/// Canonical timestamp encoding: `2026-01-01T00:00:00.000Z` (same as JS `toISOString`).
pub fn format_ts(t: &Timestamp) -> String {
    t.to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub fn ts_value(t: &Timestamp) -> Value {
    Value::String(format_ts(t))
}

pub(crate) mod ts {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(t: &Timestamp, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format_ts(t))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Timestamp, D::Error> {
        let s = String::deserialize(d)?;
        DateTime::parse_from_rfc3339(&s).map(|t| t.with_timezone(&Utc)).map_err(serde::de::Error::custom)
    }

    pub mod option {
        use super::*;

        pub fn serialize<S: Serializer>(t: &Option<Timestamp>, s: S) -> Result<S::Ok, S::Error> {
            match t {
                Some(t) => s.serialize_str(&format_ts(t)),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Timestamp>, D::Error> {
            match Option::<String>::deserialize(d)? {
                Some(s) => DateTime::parse_from_rfc3339(&s)
                    .map(|t| Some(t.with_timezone(&Utc)))
                    .map_err(serde::de::Error::custom),
                None => Ok(None),
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: String,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(with = "ts")]
    pub created_at: Timestamp,
    #[serde(with = "ts")]
    pub updated_at: Timestamp,
    #[serde(flatten)]
    pub extra: Record,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id: String,
    #[serde(with = "ts")]
    pub expires_at: Timestamp,
    pub token: String,
    #[serde(with = "ts")]
    pub created_at: Timestamp,
    #[serde(with = "ts")]
    pub updated_at: Timestamp,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
    pub user_id: String,
    #[serde(flatten)]
    pub extra: Record,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub id: String,
    pub account_id: String,
    pub provider_id: String,
    pub user_id: String,
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default, with = "ts::option")]
    pub access_token_expires_at: Option<Timestamp>,
    #[serde(default, with = "ts::option")]
    pub refresh_token_expires_at: Option<Timestamp>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(with = "ts")]
    pub created_at: Timestamp,
    #[serde(with = "ts")]
    pub updated_at: Timestamp,
    #[serde(flatten)]
    pub extra: Record,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Verification {
    pub id: String,
    pub identifier: String,
    pub value: String,
    #[serde(with = "ts")]
    pub expires_at: Timestamp,
    #[serde(with = "ts")]
    pub created_at: Timestamp,
    #[serde(with = "ts")]
    pub updated_at: Timestamp,
}

/// `{ session, user }` — the payload of `GET /get-session`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionWithUser {
    pub session: Session,
    pub user: User,
}

pub(crate) fn from_record<T: DeserializeOwned>(rec: Record) -> Result<T, AuthError> {
    serde_json::from_value(Value::Object(rec)).map_err(|e| AuthError::internal(format!("corrupt record: {e}")))
}
