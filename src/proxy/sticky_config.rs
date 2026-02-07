use serde::{Deserialize, Serialize};

// Scheduling mode enumeration
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum SchedulingMode {
    // Cache-first: Lock to the same account as much as possible; prioritize waiting during rate limiting. Significantly improves Prompt Caching hit rate.
    CacheFirst,
    // Balance: Lock to the same account; immediately switch to an alternate account when rate limited. Balances success rate and performance.
    Balance,
    // Performance-first: Pure round-robin mode. Most balanced account load, but does not utilize caching.
    PerformanceFirst,
}

impl Default for SchedulingMode {
    fn default() -> Self {
        Self::Balance
    }
}

// Sticky session configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StickySessionConfig {
    // Current scheduling mode
    pub mode: SchedulingMode,
    // Maximum wait time in Cache-first mode (seconds)
    pub max_wait_seconds: u64,
}

impl Default for StickySessionConfig {
    fn default() -> Self {
        Self {
            mode: SchedulingMode::Balance,
            max_wait_seconds: 60,
        }
    }
}
