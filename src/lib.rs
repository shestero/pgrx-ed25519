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

// todo
//use ed25519_dalek::pkcs8::DecodePublicKey;

#[pg_extern]
fn test() -> String {

    /*
    let pem = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----";

    let verifying_key = VerifyingKey::from_public_key_pem(pem)
        .expect("invalid public key PEM");
    */

    let mut csprng = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);

    let message: &[u8] = b"This is a test of the tsunami alert system.";
    let signature: Signature = signing_key.sign(message);

    let ok1 = signing_key.verify(message, &signature).is_ok();

    let verifying_key: VerifyingKey = signing_key.verifying_key();
    let ok2 = verifying_key.verify(message, &signature).is_ok();

    format!("ed25519: ok1={ok1} ok2={ok2}")
}
