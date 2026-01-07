//! Synchronization primitives with poison recovery
//!
//! This module provides extensions to standard library lock types that handle
//! lock poisoning gracefully instead of panicking. When a thread panics while
//! holding a lock, the lock becomes "poisoned" to indicate potential data
//! inconsistency. Instead of propagating panics, these utilities recover the
//! guard and log a warning.

use crate::error::{Error, Result};
use log::warn;
use std::sync::{Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Extension trait for RwLock that provides poison-recovering lock acquisition
pub trait RwLockExt<T> {
    /// Acquire a read lock, recovering from poison
    ///
    /// If the lock is poisoned, this method logs a warning and returns the
    /// guard anyway. The data may be in an inconsistent state.
    fn read_recovered(&self) -> Result<RwLockReadGuard<'_, T>>;

    /// Acquire a write lock, recovering from poison
    ///
    /// If the lock is poisoned, this method logs a warning and returns the
    /// guard anyway. Callers should be extra careful as the data may be
    /// in an inconsistent state.
    fn write_recovered(&self) -> Result<RwLockWriteGuard<'_, T>>;
}

impl<T> RwLockExt<T> for RwLock<T> {
    fn read_recovered(&self) -> Result<RwLockReadGuard<'_, T>> {
        self.read()
            .or_else(|poison: PoisonError<RwLockReadGuard<T>>| {
                warn!(
                    "⚠️  Recovered from poisoned RwLock (read) - data may be inconsistent. \
                     This indicates a previous thread panicked while holding the lock."
                );
                Ok(poison.into_inner())
            })
            .map_err(|_: PoisonError<RwLockReadGuard<T>>| Error::LockPoisoned)
    }

    fn write_recovered(&self) -> Result<RwLockWriteGuard<'_, T>> {
        self.write()
            .or_else(|poison: PoisonError<RwLockWriteGuard<T>>| {
                warn!(
                    "⚠️  Recovered from poisoned RwLock (write) - data may be inconsistent. \
                     This indicates a previous thread panicked while holding the lock. \
                     Proceeding with caution."
                );
                Ok(poison.into_inner())
            })
            .map_err(|_: PoisonError<RwLockWriteGuard<T>>| Error::LockPoisoned)
    }
}

/// Extension trait for Mutex that provides poison-recovering lock acquisition
pub trait MutexExt<T> {
    /// Acquire a mutex lock, recovering from poison
    ///
    /// If the lock is poisoned, this method logs a warning and returns the
    /// guard anyway. The data may be in an inconsistent state.
    fn lock_recovered(&self) -> Result<MutexGuard<'_, T>>;
}

impl<T> MutexExt<T> for Mutex<T> {
    fn lock_recovered(&self) -> Result<MutexGuard<'_, T>> {
        self.lock()
            .or_else(|poison: PoisonError<MutexGuard<T>>| {
                warn!(
                    "⚠️  Recovered from poisoned Mutex - data may be inconsistent. \
                     This indicates a previous thread panicked while holding the lock."
                );
                Ok(poison.into_inner())
            })
            .map_err(|_: PoisonError<MutexGuard<T>>| Error::LockPoisoned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_rwlock_poison_recovery_read() {
        let lock = Arc::new(RwLock::new(42));
        let lock_clone = lock.clone();

        // Poison the lock by panicking while holding a write guard
        let result = thread::spawn(move || {
            let mut guard = lock_clone.write().unwrap();
            *guard = 100;
            panic!("Intentional panic to poison lock");
        })
        .join();

        assert!(result.is_err(), "Thread should have panicked");

        // Now try to read with recovery
        let recovered = lock.read_recovered();
        assert!(
            recovered.is_ok(),
            "Should recover from poisoned lock: {:?}",
            recovered
        );
        assert_eq!(*recovered.unwrap(), 100, "Should see modified value");
    }

    #[test]
    fn test_rwlock_poison_recovery_write() {
        let lock = Arc::new(RwLock::new(42));
        let lock_clone = lock.clone();

        // Poison the lock
        let _ = thread::spawn(move || {
            let _guard = lock_clone.write().unwrap();
            panic!("Intentional panic");
        })
        .join();

        // Try to write with recovery
        let recovered = lock.write_recovered();
        assert!(recovered.is_ok(), "Should recover from poisoned lock");

        if let Ok(mut guard) = recovered {
            *guard = 200;
        }

        // Verify we can still use the lock
        assert_eq!(*lock.read_recovered().unwrap(), 200);
    }

    #[test]
    fn test_mutex_poison_recovery() {
        let mutex = Arc::new(Mutex::new(42));
        let mutex_clone = mutex.clone();

        // Poison the mutex
        let _ = thread::spawn(move || {
            let mut guard = mutex_clone.lock().unwrap();
            *guard = 100;
            panic!("Intentional panic");
        })
        .join();

        // Try to lock with recovery
        let recovered = mutex.lock_recovered();
        assert!(recovered.is_ok(), "Should recover from poisoned mutex");
        assert_eq!(*recovered.unwrap(), 100);
    }

    #[test]
    fn test_normal_lock_operations() {
        let lock = RwLock::new(42);

        // Normal read
        let read = lock.read_recovered().unwrap();
        assert_eq!(*read, 42);
        drop(read);

        // Normal write
        let mut write = lock.write_recovered().unwrap();
        *write = 100;
        drop(write);

        // Verify
        assert_eq!(*lock.read_recovered().unwrap(), 100);
    }
}
