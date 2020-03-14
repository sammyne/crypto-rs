use secp256k1::{self, util, Message, Signature};
use std::io::{self, Read};

pub const PRIVATE_KEY_LEN: usize = util::SECRET_KEY_SIZE;
pub const SIGNATURE_LEN: usize = util::SIGNATURE_SIZE;

pub type PrivateKey = secp256k1::SecretKey;
pub type PublicKey = secp256k1::PublicKey;

#[derive(Debug)]
pub enum Error {
    IOError(io::Error),
    SigError(secp256k1::Error),
    InvalidSigError,
}

/// @TODO: implement super::Signer
//impl super::PrivateKey for PrivateKey {
//    type PublicKey = PublicKey;
//
//    fn public(&self) -> PublicKey {
//        PublicKey::from_secret_key(&self)
//    }
//}
impl crate::Signer for PrivateKey {
    type PublicKey = PublicKey;

    fn public(&self) -> Self::PublicKey {
        PublicKey::from_secret_key(&self)
    }

    fn sign<T>(&self, _rand: &mut T, digest: &[u8]) -> Result<Vec<u8>, String>
    where
        T: Read,
    {
        sign(self, digest).map_err(|err| format!("{:?}", err))
    }
}

pub fn generate_key<T>(rand: &mut T) -> Result<PrivateKey, Error>
where
    T: Read,
{
    let mut seed = [0u8; PRIVATE_KEY_LEN];

    rand.read_exact(&mut seed)
        .map_err(|err| Error::IOError(err))?;

    PrivateKey::parse(&seed).map_err(|err| Error::SigError(err))
}

pub fn sign(priv_key: &PrivateKey, msg: &[u8]) -> Result<Vec<u8>, Error> {
    let msg = Message::parse_slice(msg).map_err(|err| Error::SigError(err))?;

    let (sig, recovery_id) = secp256k1::sign(&msg, &priv_key);
    let sig = sig.serialize();

    let mut out = Vec::with_capacity(sig.len() + 1);
    out.extend_from_slice(&sig[..]);
    out.push(recovery_id.serialize());

    Ok(out)
}

pub fn verify(pub_key: &PublicKey, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    let msg = Message::parse_slice(msg).map_err(|err| Error::SigError(err))?;

    let sig = Signature::parse_slice(&sig[..SIGNATURE_LEN]).map_err(|err| Error::SigError(err))?;

    if !secp256k1::verify(&msg, &sig, pub_key) {
        return Err(Error::InvalidSigError);
    }

    Ok(())
}
