mod hash;

pub mod ed25519;
pub mod rand;
pub mod secp256k1;
pub mod sha256;
pub mod sha512;

pub use hash::*;

pub trait PrivateKey {
    type PublicKey;

    fn public(&self) -> Self::PublicKey;
}
