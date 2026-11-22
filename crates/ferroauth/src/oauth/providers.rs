//! Provider presets.

use std::sync::Arc;

use serde_json::Value;

use super::{get_json, oidc_profile, OAuth2Provider, OAuthUserInfo, ProfileSource};

/// GitHub. Fetches `/user` and, when the email is private, `/user/emails`.
pub fn github(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    let mut p = OAuth2Provider::new(
        "github",
        client_id,
        client_secret,
        "https://github.com/login/oauth/authorize",
        "https://github.com/login/oauth/access_token",
    )
    .scopes(&["read:user", "user:email"])
    .pkce(false)
    .map_profile(|v| {
        let id = v.get("id")?;
        let login = v.get("login").and_then(Value::as_str).unwrap_or_default();
        Some(OAuthUserInfo {
            id: id.as_i64().map(|n| n.to_string()).or_else(|| id.as_str().map(str::to_string))?,
            name: v.get("name").and_then(Value::as_str).filter(|s| !s.is_empty()).unwrap_or(login).to_string(),
            email: v.get("email").and_then(Value::as_str).map(str::to_string),
            email_verified: v.get("email_verified").and_then(Value::as_bool).unwrap_or(false),
            image: v.get("avatar_url").and_then(Value::as_str).map(str::to_string),
        })
    });
    p.profile = ProfileSource::Custom(Arc::new(|http, tokens| {
        Box::pin(async move {
            let at = tokens.access_token.clone().unwrap_or_default();
            let mut user = get_json(&http, "https://api.github.com/user", &at).await?;
            let emails = get_json(&http, "https://api.github.com/user/emails", &at).await.unwrap_or(Value::Null);
            let list = emails.as_array().cloned().unwrap_or_default();
            let current = user.get("email").and_then(Value::as_str).map(str::to_string);
            let chosen = match &current {
                Some(e) => list.iter().find(|x| x.get("email").and_then(Value::as_str) == Some(e)),
                None => list.iter().find(|x| x.get("primary").and_then(Value::as_bool) == Some(true)),
            };
            if let (Some(obj), Some(chosen)) = (user.as_object_mut(), chosen) {
                obj.insert("email".into(), chosen.get("email").cloned().unwrap_or(Value::Null));
                obj.insert("email_verified".into(), chosen.get("verified").cloned().unwrap_or(Value::Bool(false)));
            }
            Ok(user)
        })
    }));
    p
}

/// Google (OIDC; profile read from the id_token).
pub fn google(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "google",
        client_id,
        client_secret,
        "https://accounts.google.com/o/oauth2/v2/auth",
        "https://oauth2.googleapis.com/token",
    )
    .param("access_type", "offline")
    .param("include_granted_scopes", "true")
}

/// Discord.
pub fn discord(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "discord",
        client_id,
        client_secret,
        "https://discord.com/api/oauth2/authorize",
        "https://discord.com/api/oauth2/token",
    )
    .scopes(&["identify", "email"])
    .userinfo_endpoint("https://discord.com/api/users/@me")
    .map_profile(|v| {
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        let id = s("id")?;
        let image = s("avatar").map(|a| {
            let ext = if a.starts_with("a_") { "gif" } else { "png" };
            format!("https://cdn.discordapp.com/avatars/{id}/{a}.{ext}")
        });
        Some(OAuthUserInfo {
            name: s("global_name").or_else(|| s("username")).unwrap_or_default(),
            email: s("email"),
            email_verified: v.get("verified").and_then(Value::as_bool).unwrap_or(false),
            image,
            id,
        })
    })
}

/// Any OIDC provider given its endpoints (e.g. Keycloak, Auth0, Okta).
pub fn oidc(
    id: impl Into<String>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
    authorization_endpoint: impl Into<String>,
    token_endpoint: impl Into<String>,
    userinfo_endpoint: Option<String>,
) -> OAuth2Provider {
    let p = OAuth2Provider::new(id, client_id, client_secret, authorization_endpoint, token_endpoint).map_profile(oidc_profile);
    match userinfo_endpoint {
        Some(u) => p.userinfo_endpoint(u),
        None => p,
    }
}
