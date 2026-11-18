//! Bounded per-process admission; durable slot/account CAS remain deployment-wide.
use super::{AccessError, Result};
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};
use zann_crypto::account_access::Transcript;
struct Bucket {
    start: Instant,
    last: Instant,
    count: u16,
}
struct State {
    buckets: HashMap<[u8; 32], Bucket>,
    pruned: Instant,
}
pub struct AccessLimiter(Mutex<State>);
impl Default for AccessLimiter {
    fn default() -> Self {
        Self(Mutex::new(State {
            buckets: HashMap::new(),
            pruned: Instant::now(),
        }))
    }
}
impl AccessLimiter {
    pub(crate) fn consume(&self, locator: &str, source: Option<&str>) -> Result<()> {
        if locator.len() > 320 {
            return Err(AccessError::Rejected);
        }
        self.admit(&[
            (key("locator", &locator.trim().to_lowercase()), 5),
            (key("source", &source_key(source)), 20),
            // Only consume reaches the KDF; login must not share its global budget.
            (key("consume-global", ""), 60),
        ])
    }
    pub(crate) fn login(&self, source: Option<&str>) -> Result<()> {
        self.admit(&[(key("login-source", &source_key(source)), 20)])
    }
    /// Callers must authenticate the operation or session first, so anonymous
    /// requests cannot allocate limiter entries.
    pub(crate) fn resume(&self, operation: uuid::Uuid) -> Result<()> {
        self.admit(&[(key("resume", &operation.to_string()), 30)])
    }
    fn admit(&self, keys: &[([u8; 32], u16)]) -> Result<()> {
        let now = Instant::now();
        let mut state = self
            .0
            .lock()
            .map_err(|_| AccessError::Configuration("account access limiter poisoned"))?;
        if now.duration_since(state.pruned) >= Duration::from_secs(60) {
            state
                .buckets
                .retain(|_, b| now.duration_since(b.last) < Duration::from_secs(900));
            state.pruned = now;
        }
        let missing = keys
            .iter()
            .filter(|(key, _)| !state.buckets.contains_key(key))
            .count();
        if state.buckets.len() + missing > 8192 {
            return Err(AccessError::Capacity);
        }
        for (key, max) in keys {
            if state.buckets.get(key).is_some_and(|b| {
                now.duration_since(b.start) < Duration::from_secs(60) && b.count >= *max
            }) {
                return Err(AccessError::RateLimited);
            }
        }
        for (key, _) in keys {
            let bucket = state.buckets.entry(*key).or_insert(Bucket {
                start: now,
                last: now,
                count: 0,
            });
            if now.duration_since(bucket.start) >= Duration::from_secs(60) {
                bucket.start = now;
                bucket.count = 0;
            }
            bucket.last = now;
            bucket.count += 1;
        }
        Ok(())
    }
}
/// IPv6 sources are bucketed per /64: one subscriber usually controls a whole /64.
fn source_key(source: Option<&str>) -> String {
    use std::net::{IpAddr, Ipv6Addr};
    match source.map(str::parse::<IpAddr>) {
        Some(Ok(IpAddr::V6(ip))) => match ip.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => format!(
                "{}/64",
                Ipv6Addr::from(u128::from(ip) & !(u128::from(u64::MAX)))
            ),
        },
        Some(Ok(IpAddr::V4(ip))) => ip.to_string(),
        Some(Err(_)) | None => source.unwrap_or("").to_owned(),
    }
}
fn key(label: &str, value: &str) -> [u8; 32] {
    Transcript::new("zann account admission v1")
        .field(label.as_bytes())
        .field(value.as_bytes())
        .digest()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_sources_share_one_bucket_per_64() {
        assert_eq!(
            source_key(Some("2001:db8:1:2:aaaa::1")),
            source_key(Some("2001:db8:1:2:ffff::9"))
        );
        assert_ne!(
            source_key(Some("2001:db8:1:2::1")),
            source_key(Some("2001:db8:1:3::1"))
        );
        assert_eq!(source_key(Some("::ffff:192.0.2.7")), "192.0.2.7");
        assert_eq!(source_key(Some("192.0.2.7")), "192.0.2.7");
    }

    #[test]
    fn exhausted_consume_budget_does_not_block_login() {
        let limiter = AccessLimiter::default();
        for n in 0..60 {
            limiter
                .consume(
                    &format!("user{n}@example.test"),
                    Some(&format!("192.0.2.{n}")),
                )
                .expect("consume admitted");
        }
        assert!(matches!(
            limiter.consume("late@example.test", Some("198.51.100.1")),
            Err(AccessError::RateLimited)
        ));
        limiter
            .login(Some("198.51.100.1"))
            .expect("login keeps its own budget");
    }

    #[test]
    fn ipv6_login_source_is_limited_per_64() {
        let limiter = AccessLimiter::default();
        for n in 0..20 {
            limiter
                .login(Some(&format!("2001:db8:7:7::{n:x}")))
                .expect("login admitted");
        }
        assert!(matches!(
            limiter.login(Some("2001:db8:7:7::ffff")),
            Err(AccessError::RateLimited)
        ));
    }
}
