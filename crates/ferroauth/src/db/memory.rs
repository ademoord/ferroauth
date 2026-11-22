//! In-memory adapter, for tests and prototyping. Enforces `unique` fields.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::RwLock;

use async_trait::async_trait;
use serde_json::Value;

use super::{Adapter, Connector, DbError, DbResult, FindMany, Op, Record, SortDirection, Where};
use crate::schema::Schema;

#[derive(Default)]
pub struct MemoryAdapter {
    tables: RwLock<HashMap<String, Vec<Record>>>,
    schema: RwLock<Schema>,
}

impl MemoryAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of a table, handy in tests.
    pub fn dump(&self, model: &str) -> Vec<Record> {
        self.tables.read().unwrap().get(model).cloned().unwrap_or_default()
    }

    fn check_unique(&self, model: &str, rows: &[Record], candidate: &Record, skip_id: Option<&Value>) -> DbResult<()> {
        let schema = self.schema.read().unwrap();
        let Some(table) = schema.table(model) else { return Ok(()) };
        for field in table.fields.iter().filter(|f| f.unique) {
            let Some(value) = candidate.get(&field.name).filter(|v| !v.is_null()) else { continue };
            let clash = rows.iter().any(|row| {
                row.get(&field.name) == Some(value) && (skip_id.is_none() || row.get("id") != skip_id)
            });
            if clash {
                return Err(DbError::UniqueViolation(format!("{model}.{}", field.name)));
            }
        }
        if skip_id.is_none() {
            if let Some(id) = candidate.get("id") {
                if rows.iter().any(|row| row.get("id") == Some(id)) {
                    return Err(DbError::UniqueViolation(format!("{model}.id")));
                }
            }
        }
        Ok(())
    }
}

fn compare(a: &Value, b: &Value) -> Option<Ordering> {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64()?.partial_cmp(&y.as_f64()?),
        (Value::String(x), Value::String(y)) => Some(x.cmp(y)),
        (Value::Bool(x), Value::Bool(y)) => Some(x.cmp(y)),
        _ => None,
    }
}

fn loose_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        _ => a == b,
    }
}

fn clause_matches(row: &Record, w: &Where) -> bool {
    let field = row.get(&w.field).unwrap_or(&Value::Null);
    match w.op {
        Op::Eq => loose_eq(field, &w.value),
        Op::Ne => !loose_eq(field, &w.value),
        Op::Lt => compare(field, &w.value) == Some(Ordering::Less),
        Op::Lte => matches!(compare(field, &w.value), Some(Ordering::Less | Ordering::Equal)),
        Op::Gt => compare(field, &w.value) == Some(Ordering::Greater),
        Op::Gte => matches!(compare(field, &w.value), Some(Ordering::Greater | Ordering::Equal)),
        Op::In => w.value.as_array().is_some_and(|vs| vs.iter().any(|v| loose_eq(field, v))),
        Op::Contains | Op::StartsWith | Op::EndsWith => match (field.as_str(), w.value.as_str()) {
            (Some(f), Some(v)) => match w.op {
                Op::Contains => f.contains(v),
                Op::StartsWith => f.starts_with(v),
                _ => f.ends_with(v),
            },
            _ => false,
        },
    }
}

pub(crate) fn matches(row: &Record, filter: &[Where]) -> bool {
    let ands = filter.iter().filter(|w| w.connector == Connector::And).all(|w| clause_matches(row, w));
    let mut ors = filter.iter().filter(|w| w.connector == Connector::Or).peekable();
    let ors_ok = ors.peek().is_none() || ors.any(|w| clause_matches(row, w));
    ands && ors_ok
}

#[async_trait]
impl Adapter for MemoryAdapter {
    async fn init(&self, schema: &Schema, _migrate: bool) -> DbResult<()> {
        *self.schema.write().unwrap() = schema.clone();
        Ok(())
    }

    async fn create(&self, model: &str, data: Record) -> DbResult<Record> {
        let mut tables = self.tables.write().unwrap();
        let rows = tables.entry(model.to_string()).or_default();
        self.check_unique(model, rows, &data, None)?;
        rows.push(data.clone());
        Ok(data)
    }

    async fn find_one(&self, model: &str, filter: &[Where]) -> DbResult<Option<Record>> {
        let tables = self.tables.read().unwrap();
        Ok(tables.get(model).and_then(|rows| rows.iter().find(|r| matches(r, filter)).cloned()))
    }

    async fn find_many(&self, model: &str, filter: &[Where], opts: FindMany) -> DbResult<Vec<Record>> {
        let tables = self.tables.read().unwrap();
        let mut rows: Vec<Record> =
            tables.get(model).map(|rows| rows.iter().filter(|r| matches(r, filter)).cloned().collect()).unwrap_or_default();
        if let Some((field, dir)) = &opts.sort_by {
            rows.sort_by(|a, b| {
                let ord = compare(a.get(field).unwrap_or(&Value::Null), b.get(field).unwrap_or(&Value::Null))
                    .unwrap_or(Ordering::Equal);
                if *dir == SortDirection::Desc {
                    ord.reverse()
                } else {
                    ord
                }
            });
        }
        let offset = opts.offset.unwrap_or(0);
        let limit = opts.limit.unwrap_or(usize::MAX);
        Ok(rows.into_iter().skip(offset).take(limit).collect())
    }

    async fn update(&self, model: &str, filter: &[Where], data: Record) -> DbResult<Option<Record>> {
        let mut tables = self.tables.write().unwrap();
        let Some(rows) = tables.get_mut(model) else { return Ok(None) };
        let Some(idx) = rows.iter().position(|r| matches(r, filter)) else { return Ok(None) };
        let mut updated = rows[idx].clone();
        updated.extend(data);
        let id = updated.get("id").cloned();
        self.check_unique(model, rows, &updated, Some(id.as_ref().unwrap_or(&Value::Null)))?;
        rows[idx] = updated.clone();
        Ok(Some(updated))
    }

    async fn update_many(&self, model: &str, filter: &[Where], data: Record) -> DbResult<u64> {
        let mut tables = self.tables.write().unwrap();
        let Some(rows) = tables.get_mut(model) else { return Ok(0) };
        let mut n = 0;
        for row in rows.iter_mut().filter(|r| matches(r, filter)) {
            row.extend(data.clone());
            n += 1;
        }
        Ok(n)
    }

    async fn delete(&self, model: &str, filter: &[Where]) -> DbResult<()> {
        let mut tables = self.tables.write().unwrap();
        if let Some(rows) = tables.get_mut(model) {
            if let Some(idx) = rows.iter().position(|r| matches(r, filter)) {
                rows.remove(idx);
            }
        }
        Ok(())
    }

    async fn delete_many(&self, model: &str, filter: &[Where]) -> DbResult<u64> {
        let mut tables = self.tables.write().unwrap();
        let Some(rows) = tables.get_mut(model) else { return Ok(0) };
        let before = rows.len();
        rows.retain(|r| !matches(r, filter));
        Ok((before - rows.len()) as u64)
    }

    async fn count(&self, model: &str, filter: &[Where]) -> DbResult<u64> {
        let tables = self.tables.read().unwrap();
        Ok(tables.get(model).map(|rows| rows.iter().filter(|r| matches(r, filter)).count()).unwrap_or(0) as u64)
    }
}
