//! SQL adapter on top of `sqlx::Any` (SQLite, Postgres, MySQL).
//!
//! Storage conventions (portable across all three databases):
//! - strings and dates are text; dates are RFC 3339 with milliseconds
//! - booleans and integers are 64-bit integers

use std::sync::RwLock;

use async_trait::async_trait;
use serde_json::Value;
use sqlx::any::{AnyArguments, AnyPoolOptions, AnyRow};
use sqlx::query::Query;
use sqlx::{Any, AnyPool, Row};

use super::{Adapter, Connector, DbError, DbResult, FindMany, Op, Record, SortDirection, Where};
use crate::schema::{Field, FieldType, Schema, Table};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialect {
    Sqlite,
    Postgres,
    MySql,
}

impl Dialect {
    pub fn from_url(url: &str) -> Option<Self> {
        if url.starts_with("sqlite:") {
            Some(Self::Sqlite)
        } else if url.starts_with("postgres:") || url.starts_with("postgresql:") {
            Some(Self::Postgres)
        } else if url.starts_with("mysql:") || url.starts_with("mariadb:") {
            Some(Self::MySql)
        } else {
            None
        }
    }

    fn quote(self, ident: &str) -> String {
        match self {
            Self::MySql => format!("`{}`", ident.replace('`', "``")),
            _ => format!("\"{}\"", ident.replace('"', "\"\"")),
        }
    }

    fn column_type(self, field: Option<&Field>) -> &'static str {
        let ty = field.map(|f| f.ty).unwrap_or(FieldType::String);
        let keyed = field.is_none_or(|f| f.unique || f.index || f.references.is_some());
        match (self, ty) {
            (Self::Sqlite, FieldType::String | FieldType::Date) => "TEXT",
            (Self::Sqlite, _) => "INTEGER",
            (Self::Postgres, FieldType::String | FieldType::Date) => "TEXT",
            (Self::Postgres, _) => "BIGINT",
            (Self::MySql, FieldType::Date) => "VARCHAR(32)",
            (Self::MySql, FieldType::String) if keyed => "VARCHAR(255)",
            (Self::MySql, FieldType::String) => "TEXT",
            (Self::MySql, _) => "BIGINT",
        }
    }
}

pub struct SqlxAdapter {
    pool: AnyPool,
    dialect: Dialect,
    schema: RwLock<Schema>,
}

type AnyQuery<'q> = Query<'q, Any, AnyArguments<'q>>;

fn err(e: sqlx::Error) -> DbError {
    if let sqlx::Error::Database(db) = &e {
        if db.is_unique_violation() {
            return DbError::UniqueViolation(db.message().to_string());
        }
    }
    DbError::Other(e.to_string())
}

impl SqlxAdapter {
    /// Connect using a database URL (`sqlite://auth.db?mode=rwc`, `postgres://...`, `mysql://...`).
    pub async fn connect(url: &str) -> DbResult<Self> {
        Self::connect_with(url, AnyPoolOptions::new().max_connections(10)).await
    }

    pub async fn connect_with(url: &str, options: AnyPoolOptions) -> DbResult<Self> {
        sqlx::any::install_default_drivers();
        let dialect = Dialect::from_url(url).ok_or_else(|| DbError::Other(format!("unsupported database url: {url}")))?;
        let pool = options.connect(url).await.map_err(err)?;
        Ok(Self::new(pool, dialect))
    }

    /// Wrap an existing pool. Call `sqlx::any::install_default_drivers()` before creating it.
    pub fn new(pool: AnyPool, dialect: Dialect) -> Self {
        Self { pool, dialect, schema: RwLock::new(Schema::core()) }
    }

    pub fn pool(&self) -> &AnyPool {
        &self.pool
    }

    fn table(&self, model: &str) -> DbResult<Table> {
        self.schema.read().unwrap().table(model).cloned().ok_or_else(|| DbError::UnknownTable(model.into()))
    }

    fn select_list(&self, table: &Table) -> String {
        table.columns().map(|c| self.dialect.quote(c)).collect::<Vec<_>>().join(", ")
    }

    fn create_table_sql(&self, table: &Table) -> Vec<String> {
        let d = self.dialect;
        let mut cols = vec![format!("{} {} PRIMARY KEY NOT NULL", d.quote("id"), d.column_type(None))];
        for f in &table.fields {
            cols.push(self.column_def(f, true));
        }
        let mut stmts = vec![format!("CREATE TABLE IF NOT EXISTS {} ({})", d.quote(&table.name), cols.join(", "))];
        stmts.extend(self.index_sql(table, false));
        stmts
    }

    fn column_def(&self, f: &Field, in_create: bool) -> String {
        let d = self.dialect;
        let mut def = format!("{} {}", d.quote(&f.name), d.column_type(Some(f)));
        // Columns added to an existing table must be nullable.
        if f.required && in_create {
            def.push_str(" NOT NULL");
        }
        if f.unique && in_create {
            def.push_str(" UNIQUE");
        }
        if let Some(r) = &f.references {
            def.push_str(&format!(" REFERENCES {}({})", d.quote(&r.model), d.quote(&r.field)));
            if r.on_delete_cascade {
                def.push_str(" ON DELETE CASCADE");
            }
        }
        def
    }

    fn index_sql(&self, table: &Table, include_unique: bool) -> Vec<String> {
        let d = self.dialect;
        let if_not_exists = if d == Dialect::MySql { "" } else { "IF NOT EXISTS " };
        table
            .fields
            .iter()
            .filter(|f| (f.index && !f.unique) || (include_unique && f.unique))
            .map(|f| {
                let unique = if f.unique { "UNIQUE " } else { "" };
                format!(
                    "CREATE {unique}INDEX {if_not_exists}{} ON {}({})",
                    d.quote(&format!("{}_{}_idx", table.name, f.name)),
                    d.quote(&table.name),
                    d.quote(&f.name)
                )
            })
            .collect()
    }

    async fn column_exists(&self, table: &str, column: &str) -> bool {
        let d = self.dialect;
        // Table-qualified on purpose: SQLite treats an unknown bare "identifier" as a string literal.
        let sql = format!("SELECT {t}.{} FROM {t} WHERE 1 = 0", d.quote(column), t = d.quote(table));
        sqlx::query::<Any>(&sql).fetch_all(&self.pool).await.is_ok()
    }

    async fn migrate(&self, schema: &Schema) -> DbResult<()> {
        for table in &schema.tables {
            for stmt in self.create_table_sql(table) {
                if let Err(e) = sqlx::query::<Any>(&stmt).execute(&self.pool).await {
                    // MySQL has no `CREATE INDEX IF NOT EXISTS`; duplicate index errors are expected.
                    if !(self.dialect == Dialect::MySql && stmt.starts_with("CREATE") && stmt.contains("INDEX")) {
                        return Err(err(e));
                    }
                }
            }
            for f in &table.fields {
                if !self.column_exists(&table.name, &f.name).await {
                    tracing::info!(table = %table.name, column = %f.name, "adding missing column");
                    let stmt = format!("ALTER TABLE {} ADD COLUMN {}", self.dialect.quote(&table.name), self.column_def(f, false));
                    sqlx::query::<Any>(&stmt).execute(&self.pool).await.map_err(err)?;
                    if f.unique {
                        let one = Table::new(table.name.clone(), vec![f.clone()]);
                        for stmt in self.index_sql(&one, true) {
                            sqlx::query::<Any>(&stmt).execute(&self.pool).await.map_err(err)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// Accumulates SQL text and typed bind values with dialect-correct placeholders.
struct Sql {
    dialect: Dialect,
    text: String,
    binds: Vec<(FieldType, Value)>,
}

impl Sql {
    fn new(dialect: Dialect, text: impl Into<String>) -> Self {
        Self { dialect, text: text.into(), binds: Vec::new() }
    }

    fn push(&mut self, s: &str) {
        self.text.push_str(s);
    }

    fn bind(&mut self, ty: FieldType, v: Value) {
        self.binds.push((ty, v));
        match self.dialect {
            Dialect::Postgres => self.text.push_str(&format!("${}", self.binds.len())),
            _ => self.text.push('?'),
        }
    }

    fn push_where(&mut self, table: &Table, filter: &[Where]) -> DbResult<()> {
        if filter.is_empty() {
            return Ok(());
        }
        let ands: Vec<_> = filter.iter().filter(|w| w.connector == Connector::And).collect();
        let ors: Vec<_> = filter.iter().filter(|w| w.connector == Connector::Or).collect();
        self.push(" WHERE ");
        if !ands.is_empty() {
            self.push("(");
            for (i, w) in ands.iter().enumerate() {
                if i > 0 {
                    self.push(" AND ");
                }
                self.push_clause(table, w)?;
            }
            self.push(")");
        }
        if !ors.is_empty() {
            if !ands.is_empty() {
                self.push(" AND ");
            }
            self.push("(");
            for (i, w) in ors.iter().enumerate() {
                if i > 0 {
                    self.push(" OR ");
                }
                self.push_clause(table, w)?;
            }
            self.push(")");
        }
        Ok(())
    }

    fn push_clause(&mut self, table: &Table, w: &Where) -> DbResult<()> {
        let ty = table.field_type(&w.field).ok_or_else(|| DbError::UnknownField(w.field.clone()))?;
        let col = self.dialect.quote(&w.field);
        if w.value.is_null() && matches!(w.op, Op::Eq | Op::Ne) {
            self.push(&format!("{col} IS {}NULL", if w.op == Op::Ne { "NOT " } else { "" }));
            return Ok(());
        }
        let like = |s: &str| s.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
        match w.op {
            Op::In => {
                let values = w.value.as_array().cloned().unwrap_or_default();
                if values.is_empty() {
                    self.push("1 = 0");
                    return Ok(());
                }
                self.push(&format!("{col} IN ("));
                for (i, v) in values.into_iter().enumerate() {
                    if i > 0 {
                        self.push(", ");
                    }
                    self.bind(ty, v);
                }
                self.push(")");
            }
            Op::Contains | Op::StartsWith | Op::EndsWith => {
                let s = like(w.value.as_str().unwrap_or_default());
                let pattern = match w.op {
                    Op::Contains => format!("%{s}%"),
                    Op::StartsWith => format!("{s}%"),
                    _ => format!("%{s}"),
                };
                self.push(&format!("{col} LIKE "));
                self.bind(FieldType::String, Value::String(pattern));
                self.push(" ESCAPE '\\'");
            }
            op => {
                let sym = match op {
                    Op::Eq => "=",
                    Op::Ne => "<>",
                    Op::Lt => "<",
                    Op::Lte => "<=",
                    Op::Gt => ">",
                    _ => ">=",
                };
                self.push(&format!("{col} {sym} "));
                self.bind(ty, w.value.clone());
            }
        }
        Ok(())
    }

    fn build(&self) -> DbResult<AnyQuery<'_>> {
        let mut q = sqlx::query::<Any>(&self.text);
        for (ty, v) in &self.binds {
            q = bind_value(q, *ty, v)?;
        }
        Ok(q)
    }
}

fn bind_value<'q>(q: AnyQuery<'q>, ty: FieldType, v: &Value) -> DbResult<AnyQuery<'q>> {
    Ok(match ty {
        FieldType::String | FieldType::Date => match v {
            Value::Null => q.bind(None::<String>),
            Value::String(s) => q.bind(Some(s.clone())),
            other => q.bind(Some(other.to_string())),
        },
        FieldType::Integer | FieldType::Boolean => match v {
            Value::Null => q.bind(None::<i64>),
            Value::Bool(b) => q.bind(Some(*b as i64)),
            Value::Number(n) => q.bind(Some(n.as_i64().ok_or_else(|| DbError::Other(format!("not an integer: {n}")))?)),
            Value::String(s) => q.bind(Some(s.parse::<i64>().map_err(|_| DbError::Other(format!("not an integer: {s}")))?)),
            other => return Err(DbError::Other(format!("cannot bind {other} as integer"))),
        },
    })
}

fn decode_row(table: &Table, row: &AnyRow) -> DbResult<Record> {
    let mut rec = Record::new();
    for (i, col) in table.columns().enumerate() {
        let ty = table.field_type(col).unwrap_or(FieldType::String);
        let value = match ty {
            FieldType::String | FieldType::Date => {
                row.try_get::<Option<String>, _>(i).map_err(|e| DbError::Other(e.to_string()))?.map(Value::String)
            }
            FieldType::Integer => row.try_get::<Option<i64>, _>(i).map_err(|e| DbError::Other(e.to_string()))?.map(Value::from),
            FieldType::Boolean => match row.try_get::<Option<i64>, _>(i) {
                Ok(v) => v.map(|n| Value::Bool(n != 0)),
                Err(_) => row.try_get::<Option<bool>, _>(i).map_err(|e| DbError::Other(e.to_string()))?.map(Value::Bool),
            },
        };
        rec.insert(col.to_string(), value.unwrap_or(Value::Null));
    }
    Ok(rec)
}

#[async_trait]
impl Adapter for SqlxAdapter {
    async fn init(&self, schema: &Schema, migrate: bool) -> DbResult<()> {
        *self.schema.write().unwrap() = schema.clone();
        if self.dialect == Dialect::Sqlite {
            let _ = sqlx::query::<Any>("PRAGMA foreign_keys = ON").execute(&self.pool).await;
        }
        if migrate {
            self.migrate(schema).await?;
        }
        Ok(())
    }

    async fn create(&self, model: &str, data: Record) -> DbResult<Record> {
        let table = self.table(model)?;
        let d = self.dialect;
        let mut sql = Sql::new(d, format!("INSERT INTO {} (", d.quote(model)));
        let cols: Vec<&str> = table.columns().filter(|c| data.contains_key(*c)).collect();
        sql.push(&cols.iter().map(|c| d.quote(c)).collect::<Vec<_>>().join(", "));
        sql.push(") VALUES (");
        for (i, c) in cols.iter().enumerate() {
            if i > 0 {
                sql.push(", ");
            }
            sql.bind(table.field_type(c).unwrap(), data[*c].clone());
        }
        sql.push(")");
        sql.build()?.execute(&self.pool).await.map_err(err)?;
        let mut out = Record::new();
        for c in table.columns() {
            out.insert(c.to_string(), data.get(c).cloned().unwrap_or(Value::Null));
        }
        Ok(out)
    }

    async fn find_one(&self, model: &str, filter: &[Where]) -> DbResult<Option<Record>> {
        let opts = FindMany { limit: Some(1), ..Default::default() };
        Ok(self.find_many(model, filter, opts).await?.into_iter().next())
    }

    async fn find_many(&self, model: &str, filter: &[Where], opts: FindMany) -> DbResult<Vec<Record>> {
        let table = self.table(model)?;
        let d = self.dialect;
        let mut sql = Sql::new(d, format!("SELECT {} FROM {}", self.select_list(&table), d.quote(model)));
        sql.push_where(&table, filter)?;
        if let Some((field, dir)) = &opts.sort_by {
            table.field_type(field).ok_or_else(|| DbError::UnknownField(field.clone()))?;
            sql.push(&format!(" ORDER BY {} {}", d.quote(field), if *dir == SortDirection::Desc { "DESC" } else { "ASC" }));
        }
        match (opts.limit, opts.offset) {
            (Some(l), Some(o)) => sql.push(&format!(" LIMIT {l} OFFSET {o}")),
            (Some(l), None) => sql.push(&format!(" LIMIT {l}")),
            (None, Some(o)) => sql.push(&format!(" LIMIT {} OFFSET {o}", i64::MAX)),
            (None, None) => {}
        }
        let rows = sql.build()?.fetch_all(&self.pool).await.map_err(err)?;
        rows.iter().map(|r| decode_row(&table, r)).collect()
    }

    async fn update(&self, model: &str, filter: &[Where], data: Record) -> DbResult<Option<Record>> {
        let Some(existing) = self.find_one(model, filter).await? else { return Ok(None) };
        let id = existing.get("id").cloned().unwrap_or(Value::Null);
        self.update_many(model, &[Where::eq("id", id.clone())], data).await?;
        self.find_one(model, &[Where::eq("id", id)]).await
    }

    async fn update_many(&self, model: &str, filter: &[Where], data: Record) -> DbResult<u64> {
        if data.is_empty() {
            return self.count(model, filter).await;
        }
        let table = self.table(model)?;
        let d = self.dialect;
        let mut sql = Sql::new(d, format!("UPDATE {} SET ", d.quote(model)));
        for (i, (k, v)) in data.into_iter().enumerate() {
            let ty = table.field_type(&k).ok_or_else(|| DbError::UnknownField(k.clone()))?;
            if i > 0 {
                sql.push(", ");
            }
            sql.push(&format!("{} = ", d.quote(&k)));
            sql.bind(ty, v);
        }
        sql.push_where(&table, filter)?;
        Ok(sql.build()?.execute(&self.pool).await.map_err(err)?.rows_affected())
    }

    async fn delete(&self, model: &str, filter: &[Where]) -> DbResult<()> {
        if let Some(rec) = self.find_one(model, filter).await? {
            self.delete_many(model, &[Where::eq("id", rec.get("id").cloned().unwrap_or(Value::Null))]).await?;
        }
        Ok(())
    }

    async fn delete_many(&self, model: &str, filter: &[Where]) -> DbResult<u64> {
        let table = self.table(model)?;
        let mut sql = Sql::new(self.dialect, format!("DELETE FROM {}", self.dialect.quote(model)));
        sql.push_where(&table, filter)?;
        Ok(sql.build()?.execute(&self.pool).await.map_err(err)?.rows_affected())
    }

    async fn count(&self, model: &str, filter: &[Where]) -> DbResult<u64> {
        let table = self.table(model)?;
        let mut sql = Sql::new(self.dialect, format!("SELECT COUNT(*) FROM {}", self.dialect.quote(model)));
        sql.push_where(&table, filter)?;
        let row = sql.build()?.fetch_one(&self.pool).await.map_err(err)?;
        let n: i64 = row.try_get(0).map_err(|e| DbError::Other(e.to_string()))?;
        Ok(n as u64)
    }

    fn generate_schema_sql(&self, schema: &Schema) -> Option<String> {
        let stmts: Vec<String> = schema.tables.iter().flat_map(|t| self.create_table_sql(t)).collect();
        Some(stmts.join(";\n\n") + ";\n")
    }
}
