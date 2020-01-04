//! module ed25519 implements the Ed25519 signature algorithm. See [https://ed25519.cr.yp.to/][1]
//!
//! [1]: https://ed25519.cr.yp.to/

use std::convert::TryFrom;
use std::io::{self, Read};

use ed25519_dalek::{Keypair, SecretKey, Signature, SignatureError};

/// PUBLIC_KEY_LEN is the size, in bytes, of public keys as used in this package.
pub const PUBLIC_KEY_LEN: usize = 32;
/// PRIVATE_KEY_LEN is the size, in bytes, of private keys as used in this package
pub const PRIVATE_KEY_LEN: usize = 64;
/// SIGNATURE_LEN is the size, in bytes, of signatures generated and verified by this package
pub const SIGNATURE_LEN: usize = 64;

/// PrivateKey is the type of Ed25519 private keys
pub struct PrivateKey(Keypair);
/// PublicKey is the type of Ed25519 public keys
#[derive(Debug, Eq, PartialEq)]
pub struct PublicKey(ed25519_dalek::PublicKey);

#[derive(Debug)]
pub enum Error {
    IOError(io::Error),
    SigError(SignatureError),
}

impl super::Signer for PrivateKey {
    type PublicKey = PublicKey;

    fn public(&self) -> Self::PublicKey {
        PublicKey(self.0.public)
    }

    /// @TODO: add the SignerOpts
    fn sign<T>(&self, _rand: &mut T, digest: &[u8]) -> Result<Vec<u8>, String>
    where
        T: Read,
    {
        Ok(sign(self, digest))
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = Error;

    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        match ed25519_dalek::PublicKey::from_bytes(v) {
            Ok(pubkey) => Ok(Self(pubkey)),
            Err(err) => Err(Error::SigError(err)),
        }
    }
}

pub fn generate_key<T>(rand: &mut T) -> Result<(PrivateKey, PublicKey), Error>
where
    T: Read,
{
    let mut seed = [0u8; PRIVATE_KEY_LEN - PUBLIC_KEY_LEN];

    rand.read_exact(&mut seed)
        .map_err(|err| Error::IOError(err))?;

    let priv_key = SecretKey::from_bytes(&seed[..]).map_err(|err| Error::SigError(err))?;

    let pub_key = PublicKey((&priv_key).into());

    let priv_key = PrivateKey(Keypair {
        public: pub_key.0,
        secret: priv_key,
    });

    Ok((priv_key, pub_key))
}

pub fn sign(priv_key: &PrivateKey, msg: &[u8]) -> Vec<u8> {
    let sig = priv_key.0.sign(msg).to_bytes();

    let mut out = Vec::new();
    out.extend_from_slice(&sig[..]);

    out
}

pub fn verify(pub_key: &PublicKey, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    let sig = Signature::from_bytes(sig).map_err(|err| Error::SigError(err))?;

    pub_key
        .0
        .verify(msg, &sig)
        .map_err(|err| Error::SigError(err))
}
