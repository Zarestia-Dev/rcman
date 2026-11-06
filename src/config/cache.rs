//! Cache management types

/// Cache strategy for settings components
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CacheStrategy {
    /// Always cache everything (default)
    #[default]
    Full,
    /// LRU cache with maximum entries
    Lru(usize),
    /// No caching - always read from disk (high I/O, minimal memory)
    None,
}

impl CacheStrategy {
    /// Capacity for an LRU store; a size of 0 (rejected by [`validate`](Self::validate))
    /// falls back to 100 entries instead of panicking.
    pub(crate) fn lru_capacity(size: usize) -> std::num::NonZeroUsize {
        const FALLBACK: std::num::NonZeroUsize = std::num::NonZeroUsize::new(100).unwrap();
        std::num::NonZeroUsize::new(size).unwrap_or(FALLBACK)
    }

    /// Validate cache strategy configuration
    ///
    /// # Errors
    ///
    /// Returns error if LRU size is 0 (would panic on `NonZeroUsize`)
    pub fn validate(&self) -> crate::Result<()> {
        match self {
            CacheStrategy::Lru(size) if *size == 0 => Err(crate::Error::Config(
                "LRU cache size must be greater than 0".into(),
            )),
            _ => Ok(()),
        }
    }
}
