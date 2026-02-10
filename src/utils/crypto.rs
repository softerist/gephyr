use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use sha2::Digest;

const NONCE_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;
const LEGACY_NONCE_SEED: &[u8] = b"antigravity_salt";
const CIPHERTEXT_V2_PREFIX: &str = "v2:";
// Packed payload is nonce + ciphertext+tag; ciphertext can be empty.
const MIN_ENCRYPTED_BYTES: usize = NONCE_LEN + GCM_TAG_LEN;

fn legacy_nonce_bytes() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&LEGACY_NONCE_SEED[..NONCE_LEN]);
    nonce
}

fn derive_key_material(source: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    let hash = sha2::Sha256::digest(source.as_bytes());
    key.copy_from_slice(&hash);
    key
}

fn resolve_encryption_key_from_sources(
    env_key: Option<&str>,
    machine_uid_result: Result<String, String>,
) -> Result<[u8; 32], String> {
    if let Some(raw) = env_key {
        let key = raw.trim();
        if !key.is_empty() {
            return Ok(derive_key_material(key));
        }
    }

    let machine_uid = machine_uid_result?;
    let machine_uid = machine_uid.trim();
    if machine_uid.is_empty() {
        return Err("machine_uid_empty".to_string());
    }
    Ok(derive_key_material(machine_uid))
}

fn get_encryption_key() -> Result<[u8; 32], String> {
    let env_key = std::env::var("ABV_ENCRYPTION_KEY").ok();
    let machine_uid = machine_uid::get().map_err(|e| format!("machine_uid_unavailable: {}", e));
    resolve_encryption_key_from_sources(env_key.as_deref(), machine_uid).map_err(|e| {
        format!(
            "ERROR [E-CRYPTO-KEY-UNAVAILABLE] {}. In Docker/container environments machine UID may be unavailable. Remediation: set ABV_ENCRYPTION_KEY, restart Gephyr, then retry the failed operation (rerun OAuth login if account linking failed).",
            e
        )
    })
}

fn validate_encryption_key_from_sources(
    env_key: Option<&str>,
    machine_uid_result: Result<String, String>,
) -> Result<(), String> {
    resolve_encryption_key_from_sources(env_key, machine_uid_result).map(|_| ())
}

pub fn validate_encryption_key_prerequisites() -> Result<(), String> {
    let env_key = std::env::var("ABV_ENCRYPTION_KEY").ok();
    let machine_uid = machine_uid::get().map_err(|e| format!("machine_uid_unavailable: {}", e));
    validate_encryption_key_from_sources(env_key.as_deref(), machine_uid).map_err(|e| {
        format!(
            "ERROR [E-CRYPTO-KEY-UNAVAILABLE] {}. In Docker/container environments machine UID may be unavailable. Remediation: set ABV_ENCRYPTION_KEY, restart Gephyr, then retry the failed operation (rerun OAuth login if account linking failed).",
            e
        )
    })
}

fn looks_like_encrypted_payload(raw: &str) -> bool {
    let encoded = raw.strip_prefix(CIPHERTEXT_V2_PREFIX).unwrap_or(raw);
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
    Ok(decrypt_secret_or_plaintext(&raw).unwrap_or(raw))
}

pub fn decrypt_secret_or_plaintext(raw: &str) -> Result<String, String> {
    match decrypt_string(raw) {
        Ok(v) => Ok(v),
        Err(e) => {
            if looks_like_encrypted_payload(raw) {
                Err(e)
            } else {
                Ok(raw.to_string())
            }
        }
    }
}

pub fn encrypt_string(password: &str) -> Result<String, String> {
    let key = get_encryption_key()?;
    let cipher = Aes256Gcm::new(&key.into());

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, password.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let mut packed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    packed.extend_from_slice(&nonce_bytes);
    packed.extend_from_slice(&ciphertext);
    Ok(format!(
        "{}{}",
        CIPHERTEXT_V2_PREFIX,
        general_purpose::STANDARD.encode(packed)
    ))
}

pub fn decrypt_string(encrypted: &str) -> Result<String, String> {
    let key = get_encryption_key()?;
    let cipher = Aes256Gcm::new(&key.into());

    let is_v2 = encrypted.starts_with(CIPHERTEXT_V2_PREFIX);
    let encoded_payload = encrypted
        .strip_prefix(CIPHERTEXT_V2_PREFIX)
        .unwrap_or(encrypted);

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
    use crate::test_utils::ScopedEnvVar;
    use std::sync::{Mutex, OnceLock};

    static CRYPTO_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    #[test]
    fn resolve_key_prefers_env_var_over_machine_uid() {
        let env = Some("env-secret-key");
        let machine_uid = Ok("machine-id-123".to_string());
        let resolved = resolve_encryption_key_from_sources(env, machine_uid).expect("resolve key");
        assert_eq!(resolved, derive_key_material("env-secret-key"));
    }

    #[test]
    fn resolve_key_uses_machine_uid_when_env_missing() {
        let resolved = resolve_encryption_key_from_sources(None, Ok("machine-id-xyz".to_string()))
            .expect("resolve key");
        assert_eq!(resolved, derive_key_material("machine-id-xyz"));
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
    fn base64_payload_below_encrypted_threshold_falls_back_to_plaintext() {
        let raw = general_purpose::STANDARD.encode(vec![7u8; MIN_ENCRYPTED_BYTES - 1]);
        let decrypted = decrypt_secret_or_plaintext(&raw).expect("fallback plaintext");
        assert_eq!(decrypted, raw);
    }

    #[test]
    fn encrypted_values_decrypt_with_configured_key_source() {
        let _guard = CRYPTO_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("crypto env lock");
        let _key = ScopedEnvVar::set("ABV_ENCRYPTION_KEY", "test-migration-key");

        let encrypted = encrypt_string("persisted-secret").expect("encrypt");
        let decrypted = decrypt_secret_or_plaintext(&encrypted).expect("decrypt");

        assert_eq!(decrypted, "persisted-secret");
    }

    #[test]
    fn encrypt_string_uses_v2_prefix() {
        let _guard = CRYPTO_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("crypto env lock");
        let _key = ScopedEnvVar::set("ABV_ENCRYPTION_KEY", "test-v2-prefix-key");

        let encrypted = encrypt_string("secret").expect("encrypt");
        assert!(
            encrypted.starts_with(CIPHERTEXT_V2_PREFIX),
            "new ciphertext should use v2 prefix"
        );
    }

    #[test]
    fn decrypt_string_supports_unversioned_legacy_ciphertext() {
        let _guard = CRYPTO_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("crypto env lock");
        let _key = ScopedEnvVar::set("ABV_ENCRYPTION_KEY", "test-legacy-key");

        let v2_encrypted = encrypt_string("legacy-plaintext").expect("encrypt");
        let legacy_unversioned = v2_encrypted
            .strip_prefix(CIPHERTEXT_V2_PREFIX)
            .expect("v2 prefix")
            .to_string();

        let decrypted = decrypt_string(&legacy_unversioned).expect("decrypt legacy");
        assert_eq!(decrypted, "legacy-plaintext");
    }
}
