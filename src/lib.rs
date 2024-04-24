use pgrx::*;

use ed25519_dalek::{VerifyingKey, Verifier, SigningKey, Signature, Signer, SignatureError};
use rand::rngs::OsRng;

pg_module_magic!();

#[pg_extern]
fn ed25519_sign(text: &[u8], pub_key: &[u8], priv_key: &[u8]) -> Result<Vec<u8>, SignatureError> {
    let v = [priv_key, pub_key].concat();
    let pair: &[u8; 64] = (&v[0..64]).try_into() // TryFromSliceError
        .map_err(|_| SignatureError::new())?;
    let signing_key: SigningKey = SigningKey::from_keypair_bytes(pair)?; // SignatureError
    let signature: Signature = signing_key.sign(text);
    Ok(signature.to_vec())
}

#[pg_extern]
fn ed25519_verify(text: &[u8], sign: &[u8], pub_key: &[u8]) -> Result<bool, SignatureError> {
    let signature: Signature = Signature::from_slice(sign)?;
    let bytes: &[u8; 32] = (&pub_key[0..32]).try_into()
        .map_err(|_| SignatureError::new())?;
    let verifying_key: VerifyingKey = VerifyingKey::from_bytes(bytes)?;
    let ok: bool = verifying_key.verify(text, &signature).is_ok();
    Ok(ok)
}

