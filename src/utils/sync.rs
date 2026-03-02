//! Poison recovery extension traits for `std::sync` locks
//!
//! These traits provide poison-recovery methods for `RwLock`.

use crate::error::Result;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Extension trait for `RwLock` with poison recovery
pub trait RwLockExt<T> {
    /// Acquire a read lock, recovering from poison errors
    fn read_recovered(&self) -> Result<RwLockReadGuard<'_, T>>;

    /// Acquire a write lock, recovering from poison errors
    fn write_recovered(&self) -> Result<RwLockWriteGuard<'_, T>>;
}

impl<T> RwLockExt<T> for RwLock<T> {
    fn read_recovered(&self) -> Result<RwLockReadGuard<'_, T>> {
        match self.read() {
            Ok(guard) => Ok(guard),
            Err(poisoned) => {
                log::warn!("RwLock was poisoned (read), recovering");
                Ok(poisoned.into_inner())
            }
        }
    }

    fn write_recovered(&self) -> Result<RwLockWriteGuard<'_, T>> {
        match self.write() {
            Ok(guard) => Ok(guard),
            Err(poisoned) => {
                log::warn!("RwLock was poisoned (write), recovering");
                Ok(poisoned.into_inner())
            }
        }
    }
}
