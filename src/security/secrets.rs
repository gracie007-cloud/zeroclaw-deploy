// Encrypted secret store — defense-in-depth for API keys and tokens.
//
// Secrets are encrypted using a random key stored in `~/.zeroclaw/.secret_key`
// with restrictive file permissions (0600). The config file stores only
// hex-encoded ciphertext, never plaintext keys.
//
// This prevents:
//   - Plaintext exposure in config files
//   - Casual `grep` or `git log` leaks
//   - Accidental commit of raw API keys
//
// For sovereign users who prefer plaintext, `secrets.encrypt = false` disables this.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Length of the random encryption key in bytes.
const KEY_LEN: usize = 32;

/// Manages encrypted storage of secrets (API keys, tokens, etc.)
#[derive(Debug, Clone)]
pub struct SecretStore {
    /// Path to the key file (`~/.zeroclaw/.secret_key`)
    key_path: PathBuf,
    /// Whether encryption is enabled
    enabled: bool,
}

impl SecretStore {
    /// Create a new secret store rooted at the given directory.
    pub fn new(zeroclaw_dir: &Path, enabled: bool) -> Self {
        Self {
            key_path: zeroclaw_dir.join(".secret_key"),
            enabled,
        }
    }

    /// Encrypt a plaintext secret. Returns hex-encoded ciphertext prefixed with `enc:`.
    /// If encryption is disabled, returns the plaintext as-is.
    pub fn encrypt(&self, plaintext: &str) -> Result<String> {
        if !self.enabled || plaintext.is_empty() {
            return Ok(plaintext.to_string());
        }

        let key = self.load_or_create_key()?;
        let ciphertext = xor_cipher(plaintext.as_bytes(), &key);
        Ok(format!("enc:{}", hex_encode(&ciphertext)))
    }

    /// Decrypt a secret. If the value starts with `enc:`, it's decrypted.
    /// Otherwise, it's returned as-is (backward-compatible with plaintext configs).
    pub fn decrypt(&self, value: &str) -> Result<String> {
        if !value.starts_with("enc:") {
            return Ok(value.to_string());
        }

        let hex_str = &value[4..]; // strip "enc:" prefix
        let ciphertext =
            hex_decode(hex_str).context("Failed to decode encrypted secret (corrupt hex)")?;
        let key = self.load_or_create_key()?;
        let plaintext_bytes = xor_cipher(&ciphertext, &key);
        String::from_utf8(plaintext_bytes)
            .context("Decrypted secret is not valid UTF-8 — wrong key or corrupt data")
    }

    /// Check if a value is already encrypted.
    pub fn is_encrypted(value: &str) -> bool {
        value.starts_with("enc:")
    }

    /// Load the encryption key from disk, or create one if it doesn't exist.
    fn load_or_create_key(&self) -> Result<Vec<u8>> {
        if self.key_path.exists() {
            let hex_key =
                fs::read_to_string(&self.key_path).context("Failed to read secret key file")?;
            hex_decode(hex_key.trim()).context("Secret key file is corrupt")
        } else {
            let key = generate_random_key();
            if let Some(parent) = self.key_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&self.key_path, hex_encode(&key))
                .context("Failed to write secret key file")?;

            // Set restrictive permissions (Unix only)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&self.key_path, fs::Permissions::from_mode(0o600))
                    .context("Failed to set key file permissions")?;
            }

            Ok(key)
        }
    }
}

/// XOR cipher with repeating key. Same function for encrypt and decrypt.
fn xor_cipher(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

/// Generate a random key using system entropy (UUID v4 + process ID + timestamp).
fn generate_random_key() -> Vec<u8> {
    // Use two UUIDs (32 random bytes) as our key material
    let u1 = uuid::Uuid::new_v4();
    let u2 = uuid::Uuid::new_v4();
    let mut key = Vec::with_capacity(KEY_LEN);
    key.extend_from_slice(u1.as_bytes());
    key.extend_from_slice(u2.as_bytes());
    key.truncate(KEY_LEN);
    key
}

/// Hex-encode bytes to a lowercase hex string.
fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Hex-decode a hex string to bytes.
fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        anyhow::bail!("Hex string has odd length");
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("Invalid hex at position {i}: {e}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ── SecretStore basics ─────────────────────────────────────

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let store = SecretStore::new(tmp.path(), true);
        let secret = "sk-my-secret-api-key-12345";

        let encrypted = store.encrypt(secret).unwrap();
        assert!(encrypted.starts_with("enc:"), "Should have enc: prefix");
        assert_ne!(encrypted, secret, "Should not be plaintext");

        let decrypted = store.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, secret, "Roundtrip must preserve original");
    }

    #[test]
    fn encrypt_empty_returns_empty() {
        let tmp = TempDir::new().unwrap();
        let store = SecretStore::new(tmp.path(), true);
        let result = store.encrypt("").unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn decrypt_plaintext_passthrough() {
        let tmp = TempDir::new().unwrap();
        let store = SecretStore::new(tmp.path(), true);
        // Values without "enc:" prefix are returned as-is (backward compat)
        let result = store.decrypt("sk-plaintext-key").unwrap();
        assert_eq!(result, "sk-plaintext-key");
    }

    #[test]
    fn disabled_store_returns_plaintext() {
        let tmp = TempDir::new().unwrap();
        let store = SecretStore::new(tmp.path(), false);
        let result = store.encrypt("sk-secret").unwrap();
        assert_eq!(result, "sk-secret", "Disabled store should not encrypt");
    }

    #[test]
    fn is_encrypted_detects_prefix() {
        assert!(SecretStore::is_encrypted("enc:aabbcc"));
        assert!(!SecretStore::is_encrypted("sk-plaintext"));
        assert!(!SecretStore::is_encrypted(""));
    }

    #[test]
    fn key_file_created_on_first_encrypt() {
        let tmp = TempDir::new().unwrap();
        let store = SecretStore::new(tmp.path(), true);
        assert!(!store.key_path.exists());

        store.encrypt("test").unwrap();
        assert!(store.key_path.exists(), "Key file should be created");

        let key_hex = fs::read_to_string(&store.key_path).unwrap();
        assert_eq!(
            key_hex.len(),
            KEY_LEN * 2,
            "Key should be {KEY_LEN} bytes hex-encoded"
        );
    }

    #[test]
    fn same_key_used_across_calls() {
        let tmp = TempDir::new().unwrap();
        let store = SecretStore::new(tmp.path(), true);

        let e1 = store.encrypt("secret").unwrap();
        let e2 = store.encrypt("secret").unwrap();
        assert_eq!(e1, e2, "Same key should produce same ciphertext");
    }

    #[test]
    fn different_stores_same_dir_interop() {
        let tmp = TempDir::new().unwrap();
        let store1 = SecretStore::new(tmp.path(), true);
        let store2 = SecretStore::new(tmp.path(), true);

        let encrypted = store1.encrypt("cross-store-secret").unwrap();
        let decrypted = store2.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, "cross-store-secret");
    }

    #[test]
    fn unicode_secret_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let store = SecretStore::new(tmp.path(), true);
        let secret = "sk-日本語テスト-émojis-🦀";

        let encrypted = store.encrypt(secret).unwrap();
        let decrypted = store.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn long_secret_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let store = SecretStore::new(tmp.path(), true);
        let secret = "a".repeat(10_000);

        let encrypted = store.encrypt(&secret).unwrap();
        let decrypted = store.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn corrupt_hex_returns_error() {
        let tmp = TempDir::new().unwrap();
        let store = SecretStore::new(tmp.path(), true);
        let result = store.decrypt("enc:not-valid-hex!!");
        assert!(result.is_err());
    }

    // ── Low-level helpers ───────────────────────────────────────

    #[test]
    fn xor_cipher_roundtrip() {
        let key = b"testkey123";
        let data = b"hello world";
        let encrypted = xor_cipher(data, key);
        let decrypted = xor_cipher(&encrypted, key);
        assert_eq!(decrypted, data);
    }

    #[test]
    fn xor_cipher_empty_key() {
        let data = b"passthrough";
        let result = xor_cipher(data, &[]);
        assert_eq!(result, data);
    }

    #[test]
    fn hex_roundtrip() {
        let data = vec![0x00, 0x01, 0xfe, 0xff, 0xab, 0xcd];
        let encoded = hex_encode(&data);
        assert_eq!(encoded, "0001feffabcd");
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn hex_decode_odd_length_fails() {
        assert!(hex_decode("abc").is_err());
    }

    #[test]
    fn hex_decode_invalid_chars_fails() {
        assert!(hex_decode("zzzz").is_err());
    }

    #[test]
    fn generate_random_key_correct_length() {
        let key = generate_random_key();
        assert_eq!(key.len(), KEY_LEN);
    }

    #[test]
    fn generate_random_key_not_all_zeros() {
        let key = generate_random_key();
        assert!(key.iter().any(|&b| b != 0), "Key should not be all zeros");
    }

    #[test]
    fn two_random_keys_differ() {
        let k1 = generate_random_key();
        let k2 = generate_random_key();
        assert_ne!(k1, k2, "Two random keys should differ");
    }

    #[cfg(unix)]
    #[test]
    fn key_file_has_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let store = SecretStore::new(tmp.path(), true);
        store.encrypt("trigger key creation").unwrap();

        let perms = fs::metadata(&store.key_path).unwrap().permissions();
        assert_eq!(
            perms.mode() & 0o777,
            0o600,
            "Key file must be owner-only (0600)"
        );
    }
}
