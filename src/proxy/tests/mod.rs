pub mod comprehensive;
pub mod security_ip_tests;
pub mod security_integration_tests;
pub mod quota_protection;

#[cfg(test)]
use once_cell::sync::Lazy;
#[cfg(test)]
use std::sync::{Mutex, MutexGuard};

#[cfg(test)]
static SECURITY_TEST_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

#[cfg(test)]
pub(crate) fn acquire_security_test_lock() -> MutexGuard<'static, ()> {
    SECURITY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
