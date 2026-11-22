//! Fixed-window, in-memory rate limiter keyed by client IP + path.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::options::RateLimitRule;

pub(crate) struct RateLimiter {
    window: u64,
    max: u32,
    rules: Vec<RateLimitRule>,
    buckets: Mutex<HashMap<String, (Instant, u32)>>,
}

impl RateLimiter {
    pub fn new(window: u64, max: u32, rules: Vec<RateLimitRule>) -> Self {
        Self { window, max, rules, buckets: Mutex::new(HashMap::new()) }
    }

    fn rule_for(&self, path: &str) -> (u64, u32) {
        self.rules
            .iter()
            .filter(|r| path.starts_with(&r.path_prefix))
            .max_by_key(|r| r.path_prefix.len())
            .map(|r| (r.window, r.max))
            .unwrap_or((self.window, self.max))
    }

    /// Record a hit; returns `false` when the limit is exceeded.
    pub fn check(&self, ip: &str, path: &str) -> bool {
        let (window, max) = self.rule_for(path);
        let window = Duration::from_secs(window);
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap();
        if buckets.len() > 10_000 {
            buckets.retain(|_, (start, _)| now.duration_since(*start) < window);
        }
        let entry = buckets.entry(format!("{ip}|{path}")).or_insert((now, 0));
        if now.duration_since(entry.0) >= window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= max
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_per_rule() {
        let rl = RateLimiter::new(10, 5, vec![RateLimitRule::new("/sign-in", 10, 2)]);
        assert!(rl.check("1.1.1.1", "/sign-in/email"));
        assert!(rl.check("1.1.1.1", "/sign-in/email"));
        assert!(!rl.check("1.1.1.1", "/sign-in/email"));
        assert!(rl.check("2.2.2.2", "/sign-in/email"));
        for _ in 0..5 {
            assert!(rl.check("1.1.1.1", "/get-session"));
        }
        assert!(!rl.check("1.1.1.1", "/get-session"));
    }
}
