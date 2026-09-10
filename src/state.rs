//! Encrypted at-rest storage for Matrix session blobs.
//!
//! Layout: `MAGIC ‖ salt(16) ‖ nonce(24) ‖ ciphertext` where the key is
//! derived from the IRC connection password with Argon2id and the
//! ciphertext is sealed with XChaCha20-Poly1305 (matrirc-style).

use anyhow::{Result, bail};
use argon2::Argon2;
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, AeadCore, KeyInit},
};
use rand_core::{OsRng, RngCore};

const MAGIC: &[u8; 8] = b"M2078SE1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const HEADER_LEN: usize = MAGIC.len() + SALT_LEN + NONCE_LEN;

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("argon2 key derivation failed: {e}"))?;
    Ok(key)
}

/// Encrypt `plaintext` under `password`.
pub fn seal(password: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let key = derive_key(password, &salt)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a blob produced by [`seal`].
pub fn unseal(password: &str, blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() <= HEADER_LEN {
        bail!("session blob too short");
    }
    let (header, ciphertext) = blob.split_at(HEADER_LEN);
    if &header[..MAGIC.len()] != MAGIC {
        bail!("session blob has bad magic");
    }
    let salt = &header[MAGIC.len()..MAGIC.len() + SALT_LEN];
    let nonce_bytes = &header[MAGIC.len() + SALT_LEN..];

    let key = derive_key(password, salt)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let nonce = chacha20poly1305::XNonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("session decryption failed (wrong password?)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let blob = seal("hunter2", b"hello session").unwrap();
        let plain = unseal("hunter2", &blob).unwrap();
        assert_eq!(plain, b"hello session");
    }

    #[test]
    fn wrong_password_fails() {
        let blob = seal("correct", b"secret").unwrap();
        assert!(unseal("wrong", &blob).is_err());
    }

    #[test]
    fn garbage_fails() {
        assert!(unseal("x", b"").is_err());
        assert!(unseal("x", MAGIC).is_err());
        let mut blob = seal("x", b"data").unwrap();
        blob[HEADER_LEN] ^= 0xff;
        assert!(unseal("x", &blob).is_err());
        let mut bad_magic = seal("x", b"data").unwrap();
        bad_magic[0] = b'X';
        assert!(unseal("x", &bad_magic).is_err());
    }

    #[test]
    fn fresh_salt_each_time() {
        let a = seal("pw", b"same").unwrap();
        let b = seal("pw", b"same").unwrap();
        assert_ne!(a, b);
    }
}
