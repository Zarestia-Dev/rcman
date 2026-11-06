//! In-memory entry cache shared by the file-per-entry and SQLite table stores.

use crate::CacheStrategy;
use serde_json::Value;
use std::collections::HashMap;

/// Cached entries, either all of them or the most recently used ones.
pub(super) enum EntryCache {
    Full(HashMap<String, Value>),
    Lru(lru::LruCache<String, Value>),
}

impl EntryCache {
    /// The cache for a strategy; `None` when the strategy keeps no cache.
    pub(super) fn new(strategy: CacheStrategy) -> Option<Self> {
        match strategy {
            CacheStrategy::Full => Some(Self::Full(HashMap::new())),
            CacheStrategy::Lru(size) => Some(Self::Lru(lru::LruCache::new(
                CacheStrategy::lru_capacity(size),
            ))),
            CacheStrategy::None => None,
        }
    }

    /// Whether the cache keeps every entry it has seen (no eviction).
    pub(super) fn is_full(&self) -> bool {
        matches!(self, Self::Full(_))
    }

    /// Look up an entry and mark it recently used.
    pub(super) fn get(&mut self, key: &str) -> Option<&Value> {
        match self {
            Self::Full(entries) => entries.get(key),
            Self::Lru(entries) => entries.get(key),
        }
    }

    /// Look up an entry without touching the eviction order.
    pub(super) fn peek(&self, key: &str) -> Option<&Value> {
        match self {
            Self::Full(entries) => entries.get(key),
            Self::Lru(entries) => entries.peek(key),
        }
    }

    pub(super) fn contains(&self, key: &str) -> bool {
        match self {
            Self::Full(entries) => entries.contains_key(key),
            Self::Lru(entries) => entries.contains(key),
        }
    }

    pub(super) fn insert(&mut self, key: String, value: Value) {
        match self {
            Self::Full(entries) => {
                entries.insert(key, value);
            }
            Self::Lru(entries) => {
                entries.put(key, value);
            }
        }
    }

    /// Insert only when the key is not cached yet.
    pub(super) fn insert_if_absent(&mut self, key: String, value: Value) {
        if !self.contains(&key) {
            self.insert(key, value);
        }
    }

    pub(super) fn remove(&mut self, key: &str) {
        match self {
            Self::Full(entries) => {
                entries.remove(key);
            }
            Self::Lru(entries) => {
                entries.pop(key);
            }
        }
    }

    /// Cached keys in no particular order.
    pub(super) fn keys(&self) -> Vec<String> {
        match self {
            Self::Full(entries) => entries.keys().cloned().collect(),
            Self::Lru(entries) => entries.iter().map(|(key, _)| key.clone()).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn no_cache_strategy_has_no_cache() {
        assert!(EntryCache::new(CacheStrategy::None).is_none());
    }

    #[test]
    fn both_variants_insert_read_and_remove() {
        for strategy in [CacheStrategy::Full, CacheStrategy::Lru(4)] {
            let mut cache = EntryCache::new(strategy).unwrap();
            cache.insert("a".into(), json!(1));
            cache.insert_if_absent("a".into(), json!(2));
            cache.insert_if_absent("b".into(), json!(3));

            assert_eq!(cache.peek("a"), Some(&json!(1)));
            assert_eq!(cache.get("b"), Some(&json!(3)));
            assert!(cache.contains("a") && !cache.contains("c"));
            let mut keys = cache.keys();
            keys.sort();
            assert_eq!(keys, ["a", "b"]);

            cache.remove("a");
            assert!(!cache.contains("a"));
            assert_eq!(cache.is_full(), matches!(strategy, CacheStrategy::Full));
        }
    }

    #[test]
    fn lru_evicts_the_least_recently_used_entry_and_full_never_evicts() {
        let mut lru = EntryCache::new(CacheStrategy::Lru(2)).unwrap();
        lru.insert("a".into(), json!(1));
        lru.insert("b".into(), json!(2));
        // `peek` leaves the order alone; `get` refreshes "a".
        assert!(lru.peek("a").is_some());
        assert!(lru.get("a").is_some());
        lru.insert("c".into(), json!(3));
        assert!(lru.contains("a") && lru.contains("c") && !lru.contains("b"));

        let mut full = EntryCache::new(CacheStrategy::Full).unwrap();
        for index in 0..1000 {
            full.insert(index.to_string(), json!(index));
        }
        assert_eq!(full.keys().len(), 1000);
    }

    #[test]
    fn a_zero_sized_lru_falls_back_instead_of_panicking() {
        let mut cache = EntryCache::new(CacheStrategy::Lru(0)).unwrap();
        cache.insert("a".into(), json!(1));
        assert!(cache.contains("a"));
    }
}
