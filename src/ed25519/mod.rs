use std::io::{self, Read};

use ed25519_dalek::{Keypair, SecretKey, Signature, SignatureError};

pub const PUBLIC_KEY_LEN: usize = 32;
pub const PRIVATE_KEY_LEN: usize = 64;

pub type PrivateKey = Keypair;
pub type PublicKey = ed25519_dalek::PublicKey;

#[derive(Debug)]
pub enum Error {
    IOError(io::Error),
    SigError(SignatureError),
}

pub fn generate_key<T>(rand: &mut T) -> Result<(PrivateKey, PublicKey), Error>
where
    T: Read,
{
    let mut seed = [0u8; PRIVATE_KEY_LEN - PUBLIC_KEY_LEN];

    rand.read_exact(&mut seed)
        .map_err(|err| Error::IOError(err))?;

    let priv_key = SecretKey::from_bytes(&seed[..]).map_err(|err| Error::SigError(err))?;
    let pub_key: PublicKey = (&priv_key).into();

    let priv_key = Keypair {
        public: pub_key,
        secret: priv_key,
    };

    Ok((priv_key, pub_key))
}

pub fn sign(priv_key: &PrivateKey, msg: &[u8]) -> Vec<u8> {
    let sig = priv_key.sign(msg).to_bytes();

    let mut out = Vec::new();
    out.extend_from_slice(&sig[..]);

    out
}

pub fn verify(pub_key: &PublicKey, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    let sig = Signature::from_bytes(sig).map_err(|err| Error::SigError(err))?;

    pub_key
        .verify(msg, &sig)
        .map_err(|err| Error::SigError(err))
}
