use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use pbkdf2::pbkdf2_hmac_array;
use rand::RngCore;
use sha2::Digest;
use std::collections::HashSet;

const NONCE_LEN: usize = 12;
const KDF_SALT_LEN: usize = 16;
const GCM_TAG_LEN: usize = 16;
const LEGACY_NONCE_BYTES: &[u8] = b"antigravity_salt";
const CIPHERTEXT_V2_PREFIX: &str = "v2:";
const CIPHERTEXT_V3_PREFIX: &str = "v3:";
const MIN_ENCRYPTED_BYTES: usize = NONCE_LEN + GCM_TAG_LEN;
const MIN_V3_ENCRYPTED_BYTES: usize = KDF_SALT_LEN + NONCE_LEN + GCM_TAG_LEN;
const RECOMMENDED_ENV_KEY_MIN_LEN: usize = 32;
const PBKDF2_ITERATIONS_V3: u32 = 210_000;

fn legacy_nonce_bytes() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&LEGACY_NONCE_BYTES[..NONCE_LEN]);
    nonce
}

fn derive_key_material_sha256(source: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    let hash = sha2::Sha256::digest(source.as_bytes());
    key.copy_from_slice(&hash);
    key
}

fn derive_key_material_pbkdf2(source: &str, salt: &[u8]) -> [u8; 32] {
    pbkdf2_hmac_array::<sha2::Sha256, 32>(source.as_bytes(), salt, PBKDF2_ITERATIONS_V3)
}

fn resolve_encryption_key_source_from_sources(
    env_key: Option<&str>,
    machine_uid_result: Result<String, String>,
) -> Result<String, String> {
    if let Some(raw) = env_key {
        let key = raw.trim();
        if !key.is_empty() {
            return Ok(key.to_string());
        }
    }

    let machine_uid = machine_uid_result?;
    let machine_uid = machine_uid.trim();
    if machine_uid.is_empty() {
        return Err("machine_uid_empty".to_string());
    }
    Ok(machine_uid.to_string())
}

#[cfg(test)]
fn resolve_encryption_key_from_sources(
    env_key: Option<&str>,
    machine_uid_result: Result<String, String>,
) -> Result<[u8; 32], String> {
    let source = resolve_encryption_key_source_from_sources(env_key, machine_uid_result)?;
    Ok(derive_key_material_sha256(&source))
}

fn get_encryption_key_source() -> Result<String, String> {
    let env_key = std::env::var("ENCRYPTION_KEY").ok();
    let machine_uid = machine_uid::get().map_err(|e| format!("machine_uid_unavailable: {}", e));
    resolve_encryption_key_source_from_sources(env_key.as_deref(), machine_uid).map_err(|e| {
        format!(
            "ERROR [E-CRYPTO-KEY-UNAVAILABLE] {}. In Docker/container environments machine UID may be unavailable. Remediation: set ENCRYPTION_KEY, restart Gephyr, then retry the failed operation (rerun OAuth login if account linking failed).",
            e
        )
    })
}

fn get_encryption_key() -> Result<[u8; 32], String> {
    let source = get_encryption_key_source()?;
    Ok(derive_key_material_sha256(&source))
}

fn validate_encryption_key_from_sources(
    env_key: Option<&str>,
    machine_uid_result: Result<String, String>,
) -> Result<(), String> {
    resolve_encryption_key_source_from_sources(env_key, machine_uid_result).map(|_| ())
}

pub fn validate_encryption_key_prerequisites() -> Result<(), String> {
    let env_key = std::env::var("ENCRYPTION_KEY").ok();
    let machine_uid = machine_uid::get().map_err(|e| format!("machine_uid_unavailable: {}", e));
    validate_encryption_key_from_sources(env_key.as_deref(), machine_uid).map_err(|e| {
        format!(
            "ERROR [E-CRYPTO-KEY-UNAVAILABLE] {}. In Docker/container environments machine UID may be unavailable. Remediation: set ENCRYPTION_KEY, restart Gephyr, then retry the failed operation (rerun OAuth login if account linking failed).",
            e
        )
    })
}

fn classify_env_encryption_key_weakness(raw: &str) -> Option<String> {
    let key = raw.trim();
    if key.is_empty() {
        return None;
    }

    if key.len() < RECOMMENDED_ENV_KEY_MIN_LEN {
        return Some(format!("length_below_{}", RECOMMENDED_ENV_KEY_MIN_LEN));
    }

    let lowercase = key.to_ascii_lowercase();
    let normalized: String = lowercase
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    let known_weak = [
        "password",
        "changeme",
        "default",
        "secret",
        "yourencryptionkeyhere",
        "yourkeyhere",
        "test",
    ];
    if known_weak.contains(&normalized.as_str()) {
        return Some("known_weak_value".to_string());
    }

    let unique_count = key.chars().collect::<HashSet<_>>().len();
    if unique_count < 10 {
        return Some("low_character_diversity".to_string());
    }

    None
}

pub fn warn_if_weak_encryption_key() {
    let Ok(raw) = std::env::var("ENCRYPTION_KEY") else {
        return;
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return;
    }
    if let Some(reason) = classify_env_encryption_key_weakness(trimmed) {
        tracing::warn!(
            "[W-CRYPTO-WEAK-KEY] weak_or_short_encryption_key_detected reason={} len={} recommendation=use_at_least_{}_high_entropy_characters",
            reason,
            trimmed.len(),
            RECOMMENDED_ENV_KEY_MIN_LEN
        );
    }
}

pub fn is_probably_encrypted_secret(raw: &str) -> bool {
    raw.starts_with(CIPHERTEXT_V3_PREFIX)
        || raw.starts_with(CIPHERTEXT_V2_PREFIX)
        || looks_like_encrypted_payload(raw)
}

pub fn preflight_verify_decryptable_secret(raw: &str) -> Result<(), String> {
    if !is_probably_encrypted_secret(raw) {
        return Ok(());
    }
    decrypt_secret_or_plaintext(raw).map(|_| ())
}

fn looks_like_encrypted_payload(raw: &str) -> bool {
    let encoded = raw
        .strip_prefix(CIPHERTEXT_V3_PREFIX)
        .or_else(|| raw.strip_prefix(CIPHERTEXT_V2_PREFIX))
        .unwrap_or(raw);
    general_purpose::STANDARD
        .decode(encoded)
        .map(|decoded| decoded.len() >= MIN_ENCRYPTED_BYTES)
        .unwrap_or(false)
}

use serde::{Deserialize, Deserializer, Serializer};

pub fn serialize_password<S>(password: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let encrypted = encrypt_string(password).map_err(serde::ser::Error::custom)?;
    serializer.serialize_str(&encrypted)
}

pub fn deserialize_password<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let encrypted = String::deserialize(deserializer)?;
    decrypt_secret_or_plaintext(&encrypted).map_err(serde::de::Error::custom)
}

pub fn serialize_secret<S>(value: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let encrypted = encrypt_string(value).map_err(serde::ser::Error::custom)?;
    serializer.serialize_str(&encrypted)
}

pub fn deserialize_secret<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    match decrypt_secret_or_plaintext(&raw) {
        Ok(v) => Ok(v),
        Err(e) => {
            tracing::warn!(
                "deserialize_secret: decryption failed, using raw value: {}",
                e
            );
            Ok(raw)
        }
    }
}

pub fn decrypt_secret_or_plaintext(raw: &str) -> Result<String, String> {
    let has_versioned_prefix =
        raw.starts_with(CIPHERTEXT_V3_PREFIX) || raw.starts_with(CIPHERTEXT_V2_PREFIX);
    match decrypt_string(raw) {
        Ok(v) => Ok(v),
        Err(e) => {
            if has_versioned_prefix || looks_like_encrypted_payload(raw) {
                Err(e)
            } else {
                Ok(raw.to_string())
            }
        }
    }
}

pub fn encrypt_string(password: &str) -> Result<String, String> {
    let key_source = get_encryption_key_source()?;
    let mut salt_bytes = [0u8; KDF_SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt_bytes);
    let key = derive_key_material_pbkdf2(&key_source, &salt_bytes);
    let cipher = Aes256Gcm::new(&key.into());

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, password.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let mut packed = Vec::with_capacity(KDF_SALT_LEN + NONCE_LEN + ciphertext.len());
    packed.extend_from_slice(&salt_bytes);
    packed.extend_from_slice(&nonce_bytes);
    packed.extend_from_slice(&ciphertext);
    Ok(format!(
        "{}{}",
        CIPHERTEXT_V3_PREFIX,
        general_purpose::STANDARD.encode(packed)
    ))
}

pub fn decrypt_string(encrypted: &str) -> Result<String, String> {
    if encrypted.starts_with(CIPHERTEXT_V3_PREFIX) {
        let key_source = get_encryption_key_source()?;
        let encoded_payload = encrypted
            .strip_prefix(CIPHERTEXT_V3_PREFIX)
            .unwrap_or(encrypted);
        let decoded = general_purpose::STANDARD
            .decode(encoded_payload)
            .map_err(|e| format!("Base64 decode failed: {}", e))?;
        if decoded.len() < MIN_V3_ENCRYPTED_BYTES {
            return Err("Decryption failed: invalid v3 payload".to_string());
        }
        let (salt_bytes, nonce_and_ciphertext) = decoded.split_at(KDF_SALT_LEN);
        let (nonce_bytes, ciphertext) = nonce_and_ciphertext.split_at(NONCE_LEN);
        let key = derive_key_material_pbkdf2(&key_source, salt_bytes);
        let cipher = Aes256Gcm::new(&key.into());
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| "Decryption failed: invalid v3 payload or mismatched key".to_string())?;
        return String::from_utf8(plaintext).map_err(|e| format!("UTF-8 conversion failed: {}", e));
    }

    let key = get_encryption_key()?;
    let cipher = Aes256Gcm::new(&key.into());

    let is_v2 = encrypted.starts_with(CIPHERTEXT_V2_PREFIX);
    let encoded_payload = encrypted.strip_prefix(CIPHERTEXT_V2_PREFIX).unwrap_or(encrypted);

    let decoded = general_purpose::STANDARD
        .decode(encoded_payload)
        .map_err(|e| format!("Base64 decode failed: {}", e))?;
    if decoded.len() > NONCE_LEN {
        let (nonce_bytes, ciphertext) = decoded.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        if let Ok(plaintext) = cipher.decrypt(nonce, ciphertext) {
            return String::from_utf8(plaintext)
                .map_err(|e| format!("UTF-8 conversion failed: {}", e));
        }
    }
    if is_v2 {
        return Err("Decryption failed: invalid v2 payload or mismatched key".to_string());
    }
    let legacy_nonce = legacy_nonce_bytes();
    let nonce = Nonce::from_slice(&legacy_nonce);
    let plaintext = cipher
        .decrypt(nonce, decoded.as_ref())
        .map_err(|e| format!("Decryption failed: {}", e))?;
    String::from_utf8(plaintext).map_err(|e| format!("UTF-8 conversion failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{lock_env, ScopedEnvVar};
    use serde::Deserialize;

    fn encrypt_v2_ciphertext_for_tests(plaintext: &str) -> String {
        let key = get_encryption_key().expect("legacy v2 key");
        let cipher = Aes256Gcm::new(&key.into());
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .expect("legacy v2 encrypt");

        let mut packed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        packed.extend_from_slice(&nonce_bytes);
        packed.extend_from_slice(&ciphertext);
        format!(
            "{}{}",
            CIPHERTEXT_V2_PREFIX,
            general_purpose::STANDARD.encode(packed)
        )
    }

    #[test]
    fn resolve_key_prefers_env_var_over_machine_uid() {
        let env = Some("env-secret-key");
        let machine_uid = Ok("machine-id-123".to_string());
        let resolved = resolve_encryption_key_from_sources(env, machine_uid).expect("resolve key");
        assert_eq!(resolved, derive_key_material_sha256("env-secret-key"));
    }

    #[test]
    fn resolve_key_uses_machine_uid_when_env_missing() {
        let resolved = resolve_encryption_key_from_sources(None, Ok("machine-id-xyz".to_string()))
            .expect("resolve key");
        assert_eq!(resolved, derive_key_material_sha256("machine-id-xyz"));
    }

    #[test]
    fn resolve_key_errors_when_no_env_and_machine_uid_fails() {
        let err =
            resolve_encryption_key_from_sources(Some(""), Err("uid-not-available".to_string()))
                .expect_err("should fail");
        assert!(err.contains("uid-not-available"));
    }

    #[test]
    fn preflight_accepts_env_key_when_machine_uid_missing() {
        let result = validate_encryption_key_from_sources(
            Some("test-env-key"),
            Err("uid-not-available".to_string()),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn preflight_fails_when_no_env_and_machine_uid_missing() {
        let err = validate_encryption_key_from_sources(None, Err("uid-not-available".to_string()))
            .expect_err("should fail");
        assert!(err.contains("uid-not-available"));
    }

    #[test]
    fn plaintext_falls_back_when_not_encrypted() {
        let raw = "plain-text-secret";
        let decrypted = decrypt_secret_or_plaintext(raw).expect("plaintext fallback");
        assert_eq!(decrypted, raw);
    }

    #[test]
    fn encrypted_like_payload_does_not_fallback_to_plaintext() {
        let raw = general_purpose::STANDARD.encode(vec![7u8; MIN_ENCRYPTED_BYTES]);
        let err = decrypt_secret_or_plaintext(&raw).expect_err("should fail closed");
        assert!(!err.is_empty());
    }

    #[test]
    fn v2_prefixed_invalid_base64_does_not_fallback_to_plaintext() {
        let err = decrypt_secret_or_plaintext("v2:abc").expect_err("should fail closed");
        assert!(!err.is_empty());
    }

    #[test]
    fn v2_prefixed_short_payload_does_not_fallback_to_plaintext() {
        let raw = format!("v2:{}", general_purpose::STANDARD.encode(vec![7u8; 4]));
        let err = decrypt_secret_or_plaintext(&raw).expect_err("should fail closed");
        assert!(!err.is_empty());
    }

    #[test]
    fn v3_prefixed_invalid_payload_does_not_fallback_to_plaintext() {
        let err = decrypt_secret_or_plaintext("v3:abc").expect_err("should fail closed");
        assert!(!err.is_empty());
    }

    #[test]
    fn base64_payload_below_encrypted_threshold_falls_back_to_plaintext() {
        let raw = general_purpose::STANDARD.encode(vec![7u8; MIN_ENCRYPTED_BYTES - 1]);
        let decrypted = decrypt_secret_or_plaintext(&raw).expect("fallback plaintext");
        assert_eq!(decrypted, raw);
    }

    #[test]
    fn encrypted_values_decrypt_with_configured_key_source() {
        let _env_guard = lock_env();
        let _key = ScopedEnvVar::set("ENCRYPTION_KEY", "test-migration-key");

        let encrypted = encrypt_string("persisted-secret").expect("encrypt");
        let decrypted = decrypt_secret_or_plaintext(&encrypted).expect("decrypt");

        assert_eq!(decrypted, "persisted-secret");
    }

    #[test]
    fn encrypt_string_uses_v3_prefix() {
        let _env_guard = lock_env();
        let _key = ScopedEnvVar::set("ENCRYPTION_KEY", "test-v3-prefix-key");

        let encrypted = encrypt_string("secret").expect("encrypt");
        assert!(
            encrypted.starts_with(CIPHERTEXT_V3_PREFIX),
            "new ciphertext should use v3 prefix"
        );
    }

    #[test]
    fn decrypt_string_supports_versioned_v2_ciphertext() {
        let _env_guard = lock_env();
        let _key = ScopedEnvVar::set("ENCRYPTION_KEY", "test-legacy-key");

        let v2_ciphertext = encrypt_v2_ciphertext_for_tests("legacy-v2-plaintext");
        let decrypted = decrypt_string(&v2_ciphertext).expect("decrypt versioned v2");
        assert_eq!(decrypted, "legacy-v2-plaintext");
    }

    #[test]
    fn decrypt_string_supports_unversioned_legacy_ciphertext() {
        let _env_guard = lock_env();
        let _key = ScopedEnvVar::set("ENCRYPTION_KEY", "test-legacy-key");

        let v2_encrypted = encrypt_v2_ciphertext_for_tests("legacy-plaintext");
        let legacy_unversioned = v2_encrypted
            .strip_prefix(CIPHERTEXT_V2_PREFIX)
            .expect("v2 prefix")
            .to_string();

        let decrypted = decrypt_string(&legacy_unversioned).expect("decrypt legacy");
        assert_eq!(decrypted, "legacy-plaintext");
    }

    #[test]
    fn deserialize_secret_falls_back_to_raw_when_decryption_fails() {
        #[derive(Deserialize)]
        struct SecretHolder {
            #[serde(deserialize_with = "crate::utils::crypto::deserialize_secret")]
            secret: String,
        }

        let parsed: SecretHolder = serde_json::from_str(r#"{"secret":"v2:abc"}"#)
            .expect("deserialization should not fail");
        assert_eq!(parsed.secret, "v2:abc");
    }

    #[test]
    fn weak_key_classifier_flags_short_keys() {
        let reason = classify_env_encryption_key_weakness("short-key").expect("weak key");
        assert!(reason.contains("length_below_"));
    }

    #[test]
    fn weak_key_classifier_flags_known_weak_values() {
        let reason = classify_env_encryption_key_weakness(
            "your_encryption_key_here________________",
        )
        .expect("known weak value");
        assert_eq!(reason, "known_weak_value");
    }

    #[test]
    fn weak_key_classifier_flags_low_diversity_values() {
        let reason =
            classify_env_encryption_key_weakness("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").expect("weak");
        assert_eq!(reason, "low_character_diversity");
    }

    #[test]
    fn weak_key_classifier_accepts_high_entropy_like_values() {
        let reason =
            classify_env_encryption_key_weakness("vM9$K2q!tL7#xP4@cN8%rD3^hS6&zQ1*");
        assert!(reason.is_none());
    }
}
