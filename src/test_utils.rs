#[cfg(test)]
use std::sync::{Mutex, OnceLock};

#[cfg(test)]
fn global_env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(test)]
pub(crate) fn lock_env() -> std::sync::MutexGuard<'static, ()> {
    global_env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
pub(crate) struct ScopedEnvVar {
    key: &'static str,
    original: Option<String>,
}

#[cfg(test)]
impl ScopedEnvVar {
    pub(crate) fn set(key: &'static str, value: &str) -> Self {
        let original = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self { key, original }
    }

    pub(crate) fn unset(key: &'static str) -> Self {
        let original = std::env::var(key).ok();
        std::env::remove_var(key);
        Self { key, original }
    }
}

#[cfg(test)]
impl Drop for ScopedEnvVar {
    fn drop(&mut self) {
        if let Some(value) = self.original.as_deref() {
            std::env::set_var(self.key, value);
        } else {
            std::env::remove_var(self.key);
        }
    }
}