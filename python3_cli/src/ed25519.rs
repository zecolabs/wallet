use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::fmt;
use zeroize::Zeroizing;

#[derive(Debug, PartialEq, Eq)]
pub struct LengthError {
    pub what: &'static str,
    pub expected: usize,
    pub got: usize,
}

impl fmt::Display for LengthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} must be {} bytes, got {}", self.what, self.expected, self.got)
    }
}

impl std::error::Error for LengthError {}

fn fixed<const N: usize>(what: &'static str, v: &[u8]) -> Result<[u8; N], LengthError> {
    v.try_into().map_err(|_| LengthError { what, expected: N, got: v.len() })
}

fn signing_key(seed: &[u8]) -> Result<SigningKey, LengthError> {
    let seed = Zeroizing::new(fixed::<32>("seed", seed)?);
    Ok(SigningKey::from_bytes(&seed))
}

pub fn public_key(seed: &[u8]) -> Result<[u8; 32], LengthError> {
    Ok(signing_key(seed)?.verifying_key().to_bytes())
}

pub fn sign(seed: &[u8], msg: &[u8]) -> Result<[u8; 64], LengthError> {
    Ok(signing_key(seed)?.sign(msg).to_bytes())
}

pub fn verify(public_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool, LengthError> {
    let pk = fixed::<32>("public key", public_key)?;
    let sig = fixed::<64>("signature", signature)?;
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return Ok(false);
    };
    Ok(vk.verify_strict(msg, &Signature::from_bytes(&sig)).is_ok())
}
