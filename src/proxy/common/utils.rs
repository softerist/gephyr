pub fn generate_random_id() -> String {
    use rand::Rng;
    rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(8)
        .map(char::from)
        .collect()
}
