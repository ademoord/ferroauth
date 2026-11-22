//! The same flows against a real SQLite database through the SQL adapter.

mod common;

use axum::http::StatusCode;
use common::*;
use ferroauth::db::{SqlxAdapter, Where};
use ferroauth::plugins::Username;
use ferroauth::Auth;
use serde_json::{json, Value};
use sqlx::any::AnyPoolOptions;

async fn sqlite() -> SqlxAdapter {
    // One connection: every `:memory:` connection is its own database.
    SqlxAdapter::connect_with("sqlite::memory:", AnyPoolOptions::new().max_connections(1)).await.unwrap()
}

#[tokio::test]
async fn full_flow_on_sqlite() {
    let auth = Auth::builder(base_options()).database(sqlite().await).plugin(Username::new()).build().await.unwrap();
    let mut c = Client::new(auth.clone());

    let res = c.post("/sign-up/email", json!({ "name": "Ada", "email": "ada@example.com", "password": "password123", "username": "ada" })).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let s = c.get("/get-session").await;
    assert_eq!(s.body["user"]["emailVerified"], false);
    assert_eq!(s.body["user"]["username"], "ada");

    let dup = c.fork().sign_up("ada@example.com", "password123").await;
    assert_eq!(dup.body["code"], "USER_ALREADY_EXISTS");

    let mut b = c.fork();
    assert_eq!(b.post("/sign-in/username", json!({ "username": "ADA", "password": "password123" })).await.status, StatusCode::OK);
    assert_eq!(c.get("/list-sessions").await.body.as_array().unwrap().len(), 2);
    c.post("/revoke-other-sessions", json!({})).await;
    assert_eq!(b.get("/get-session").await.body, Value::Null);

    c.post("/change-password", json!({ "currentPassword": "password123", "newPassword": "password456" })).await;
    c.post("/sign-out", json!({})).await;
    assert_eq!(c.post("/sign-in/email", json!({ "email": "ada@example.com", "password": "password456" })).await.status, StatusCode::OK);

    // Generic adapter operations.
    let db = auth.raw_adapter();
    assert_eq!(db.count("user", &[]).await.unwrap(), 1);
    assert_eq!(db.count("session", &[Where::eq("userId", s.body["user"]["id"].clone())]).await.unwrap(), 1);
    let found = db.find_many("user", &[Where::eq("email", "nobody@x.com").or(), Where::eq("username", "ada").or()], Default::default()).await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0]["emailVerified"], Value::Bool(false));
}

#[tokio::test]
async fn migrations_are_idempotent_and_add_columns() {
    let adapter = std::sync::Arc::new(sqlite().await);
    Auth::builder(base_options()).database_arc(adapter.clone()).build().await.unwrap();
    // Re-running with a plugin adds its columns to the existing table.
    let auth = Auth::builder(base_options()).database_arc(adapter.clone()).plugin(Username::new()).build().await.unwrap();
    let ddl = auth.generate_schema_sql().unwrap();
    assert!(ddl.contains("CREATE TABLE IF NOT EXISTS \"user\""));
    assert!(ddl.contains("\"username\" TEXT UNIQUE"));
    let mut c = Client::new(auth);
    let res = c.post("/sign-up/email", json!({ "name": "B", "email": "b@example.com", "password": "password123", "username": "bee" })).await;
    assert_eq!(res.body["user"]["username"], "bee", "{}", res.body);
    // Unique index was created for the added column.
    let dup = c.fork().post("/sign-up/email", json!({ "name": "C", "email": "c@example.com", "password": "password123", "username": "bee" })).await;
    assert_eq!(dup.status, StatusCode::UNPROCESSABLE_ENTITY);
}
