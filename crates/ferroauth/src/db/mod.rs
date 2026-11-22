//! Database layer. Storage goes through a small generic
//! adapter (`create` / `find_one` / `find_many` / `update` / `delete` / `count`
//! over JSON records), so plugins can add tables without touching adapters.
//! [`InternalAdapter`] builds the typed operations on top of it.

mod internal;
pub mod memory;
#[cfg(feature = "sqlx")]
pub mod sql;

use async_trait::async_trait;
use serde_json::Value;

use crate::schema::Schema;

pub use internal::{DatabaseHooks, InternalAdapter};
pub use memory::MemoryAdapter;
#[cfg(feature = "sqlx")]
pub use sql::{Dialect, SqlxAdapter};

/// A row: column name → JSON value. Dates are RFC 3339 strings.
pub type Record = serde_json::Map<String, Value>;

#[derive(Debug, Clone, thiserror::Error)]
pub enum DbError {
    #[error("unique constraint violated: {0}")]
    UniqueViolation(String),
    #[error("unknown table `{0}`")]
    UnknownTable(String),
    #[error("unknown field `{0}`")]
    UnknownField(String),
    #[error("{0}")]
    Other(String),
}

pub type DbResult<T> = std::result::Result<T, DbError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Lt,
    Lte,
    Gt,
    Gte,
    In,
    Contains,
    StartsWith,
    EndsWith,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Connector {
    #[default]
    And,
    Or,
}

/// A filter clause. Clauses with the `And` connector are all required; if any
/// `Or` clauses exist, at least one of them must also match:
/// `(and_1 AND and_2 ...) AND (or_1 OR or_2 ...)`.
#[derive(Clone, Debug)]
pub struct Where {
    pub field: String,
    pub op: Op,
    pub value: Value,
    pub connector: Connector,
}

impl Where {
    pub fn new(field: impl Into<String>, op: Op, value: impl Into<Value>) -> Self {
        Self { field: field.into(), op, value: value.into(), connector: Connector::And }
    }
    pub fn eq(field: impl Into<String>, value: impl Into<Value>) -> Self {
        Self::new(field, Op::Eq, value)
    }
    pub fn ne(field: impl Into<String>, value: impl Into<Value>) -> Self {
        Self::new(field, Op::Ne, value)
    }
    pub fn lt(field: impl Into<String>, value: impl Into<Value>) -> Self {
        Self::new(field, Op::Lt, value)
    }
    pub fn gt(field: impl Into<String>, value: impl Into<Value>) -> Self {
        Self::new(field, Op::Gt, value)
    }
    pub fn is_in(field: impl Into<String>, values: Vec<Value>) -> Self {
        Self::new(field, Op::In, Value::Array(values))
    }
    pub fn or(mut self) -> Self {
        self.connector = Connector::Or;
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortDirection {
    Asc,
    Desc,
}

#[derive(Clone, Debug, Default)]
pub struct FindMany {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub sort_by: Option<(String, SortDirection)>,
}

/// Storage backend. Implement this to plug in any database.
#[async_trait]
pub trait Adapter: Send + Sync + 'static {
    /// Called once when the auth instance is built. Receives the full schema
    /// (core + plugins + additional fields). When `migrate` is true the adapter
    /// should create missing tables / columns.
    async fn init(&self, schema: &Schema, migrate: bool) -> DbResult<()>;

    async fn create(&self, model: &str, data: Record) -> DbResult<Record>;
    async fn find_one(&self, model: &str, filter: &[Where]) -> DbResult<Option<Record>>;
    async fn find_many(&self, model: &str, filter: &[Where], opts: FindMany) -> DbResult<Vec<Record>>;
    /// Update the first matching record, returning it after the update.
    async fn update(&self, model: &str, filter: &[Where], data: Record) -> DbResult<Option<Record>>;
    async fn update_many(&self, model: &str, filter: &[Where], data: Record) -> DbResult<u64>;
    async fn delete(&self, model: &str, filter: &[Where]) -> DbResult<()>;
    async fn delete_many(&self, model: &str, filter: &[Where]) -> DbResult<u64>;
    async fn count(&self, model: &str, filter: &[Where]) -> DbResult<u64>;

    /// SQL DDL for the schema, if this adapter is SQL based.
    fn generate_schema_sql(&self, _schema: &Schema) -> Option<String> {
        None
    }
}
