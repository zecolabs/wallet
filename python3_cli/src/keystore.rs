use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

pub const VERSION: u32 = 2;

const KDF_NAME: &str = "argon2id";
const CIPHER_NAME: &str = "xchacha20poly1305";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const AAD_TAG: &[u8] = b"rx_crypto keystore";

const MAX_M_COST: u32 = 1 << 20;
const MAX_T_COST: u32 = 16;
const MAX_P_COST: u32 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self { m_cost: 64 * 1024, t_cost: 3, p_cost: 1 }
    }
}

#[derive(Serialize, Deserialize)]
struct KeystoreFile {
    version: u32,
    kdf: String,
    kdf_params: KdfParams,
    salt: String,
    cipher: String,
    nonce: String,
    ciphertext: String,
    #[serde(default)]
    address: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum KeystoreError {
    Format(String),
    Decrypt,
    Internal(String),
}

impl fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(m) => write!(f, "invalid keystore: {m}"),
            Self::Decrypt => write!(f, "wrong password or corrupted keystore"),
            Self::Internal(m) => write!(f, "internal error: {m}"),
        }
    }
}

impl std::error::Error for KeystoreError {}

fn fmt_err(m: impl Into<String>) -> KeystoreError {
    KeystoreError::Format(m.into())
}

fn check_params(p: &KdfParams) -> Result<(), KeystoreError> {
    if p.m_cost > MAX_M_COST || p.t_cost > MAX_T_COST || p.p_cost > MAX_P_COST {
        return Err(fmt_err("kdf params exceed allowed limits"));
    }
    Ok(())
}

fn derive_key(password: &[u8], salt: &[u8], p: &KdfParams) -> Result<Zeroizing<[u8; KEY_LEN]>, KeystoreError> {
    check_params(p)?;
    let params = Params::new(p.m_cost, p.t_cost, p.p_cost, Some(KEY_LEN))
        .map_err(|e| fmt_err(format!("bad kdf params: {e}")))?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, &mut *key)
        .map_err(|e| KeystoreError::Internal(e.to_string()))?;
    Ok(key)
}

fn build_aad(p: &KdfParams, salt: &[u8], address: &str) -> Vec<u8> {
    let mut a = Vec::with_capacity(64 + address.len());
    a.extend_from_slice(AAD_TAG);
    a.extend_from_slice(&VERSION.to_be_bytes());
    a.extend_from_slice(&p.m_cost.to_be_bytes());
    a.extend_from_slice(&p.t_cost.to_be_bytes());
    a.extend_from_slice(&p.p_cost.to_be_bytes());
    a.extend_from_slice(&(salt.len() as u32).to_be_bytes());
    a.extend_from_slice(salt);
    a.extend_from_slice(&(address.len() as u32).to_be_bytes());
    a.extend_from_slice(address.as_bytes());
    a
}

fn random<const N: usize>() -> Result<[u8; N], KeystoreError> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|e| KeystoreError::Internal(format!("rng: {e}")))?;
    Ok(b)
}

pub fn encrypt(plaintext: &[u8], password: &str, address: &str) -> Result<String, KeystoreError> {
    encrypt_with_params(plaintext, password, address, KdfParams::default())
}

pub fn encrypt_with_params(
    plaintext: &[u8],
    password: &str,
    address: &str,
    params: KdfParams,
) -> Result<String, KeystoreError> {
    let salt = random::<SALT_LEN>()?;
    let nonce = random::<NONCE_LEN>()?;
    let key = derive_key(password.as_bytes(), &salt, &params)?;
    let aad = build_aad(&params, &salt, address);

    let ct = XChaCha20Poly1305::new((&*key).into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
        .map_err(|_| KeystoreError::Internal("encryption failed".into()))?;

    let file = KeystoreFile {
        version: VERSION,
        kdf: KDF_NAME.into(),
        kdf_params: params,
        salt: hex::encode(salt),
        cipher: CIPHER_NAME.into(),
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ct),
        address: address.into(),
    };
    serde_json::to_string_pretty(&file).map_err(|e| KeystoreError::Internal(e.to_string()))
}

pub fn decrypt(keystore_json: &str, password: &str) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
    let f: KeystoreFile = serde_json::from_str(keystore_json).map_err(|e| fmt_err(e.to_string()))?;

    if f.version != VERSION {
        return Err(fmt_err(format!("unsupported keystore version {} (expected {VERSION})", f.version)));
    }
    if f.kdf != KDF_NAME {
        return Err(fmt_err(format!("unsupported kdf {:?}", f.kdf)));
    }
    if f.cipher != CIPHER_NAME {
        return Err(fmt_err(format!("unsupported cipher {:?}", f.cipher)));
    }
    let salt = hex::decode(&f.salt).map_err(|_| fmt_err("salt is not valid hex"))?;
    let nonce = hex::decode(&f.nonce).map_err(|_| fmt_err("nonce is not valid hex"))?;
    let ct = hex::decode(&f.ciphertext).map_err(|_| fmt_err("ciphertext is not valid hex"))?;
    if salt.len() != SALT_LEN {
        return Err(fmt_err(format!("salt must be {SALT_LEN} bytes")));
    }
    if nonce.len() != NONCE_LEN {
        return Err(fmt_err(format!("nonce must be {NONCE_LEN} bytes")));
    }
    if ct.len() < TAG_LEN {
        return Err(fmt_err("ciphertext too short"));
    }

    let key = derive_key(password.as_bytes(), &salt, &f.kdf_params)?;
    let aad = build_aad(&f.kdf_params, &salt, &f.address);
    XChaCha20Poly1305::new((&*key).into())
        .decrypt(XNonce::from_slice(&nonce), Payload { msg: &ct, aad: &aad })
        .map(Zeroizing::new)
        .map_err(|_| KeystoreError::Decrypt)
}