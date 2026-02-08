pub(crate) fn record_success(health_scores: &dashmap::DashMap<String, f32>, account_id: &str) {
    health_scores
        .entry(account_id.to_string())
        .and_modify(|s| *s = (*s + 0.05).min(1.0))
        .or_insert(1.0);
}

pub(crate) fn record_failure(health_scores: &dashmap::DashMap<String, f32>, account_id: &str) {
    health_scores
        .entry(account_id.to_string())
        .and_modify(|s| *s = (*s - 0.2).max(0.0))
        .or_insert(0.8);
}
