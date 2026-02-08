use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use sha2::Digest;

const NONCE_LEN: usize = 12;
const LEGACY_NONCE_SEED: &[u8] = b"antigravity_salt";

fn legacy_nonce_bytes() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&LEGACY_NONCE_SEED[..NONCE_LEN]);
    nonce
}
fn get_encryption_key() -> [u8; 32] {
    let device_id = machine_uid::get().unwrap_or_else(|_| "default".to_string());
    let mut key = [0u8; 32];
    let hash = sha2::Sha256::digest(device_id.as_bytes());
    key.copy_from_slice(&hash);
    key
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
        Err(_) => Ok(raw.to_string()),
    }
}

pub fn encrypt_string(password: &str) -> Result<String, String> {
    let key = get_encryption_key();
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
    Ok(general_purpose::STANDARD.encode(packed))
}

pub fn decrypt_string(encrypted: &str) -> Result<String, String> {
    let key = get_encryption_key();
    let cipher = Aes256Gcm::new(&key.into());

    let decoded = general_purpose::STANDARD
        .decode(encrypted)
        .map_err(|e| format!("Base64 decode failed: {}", e))?;
    if decoded.len() > NONCE_LEN {
        let (nonce_bytes, ciphertext) = decoded.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        if let Ok(plaintext) = cipher.decrypt(nonce, ciphertext) {
            return String::from_utf8(plaintext)
                .map_err(|e| format!("UTF-8 conversion failed: {}", e));
        }
    }
    let legacy_nonce = legacy_nonce_bytes();
    let nonce = Nonce::from_slice(&legacy_nonce);
    let plaintext = cipher
        .decrypt(nonce, decoded.as_ref())
        .map_err(|e| format!("Decryption failed: {}", e))?;
    String::from_utf8(plaintext).map_err(|e| format!("UTF-8 conversion failed: {}", e))
}
