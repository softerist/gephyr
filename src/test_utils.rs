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
