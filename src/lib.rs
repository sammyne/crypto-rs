pub mod ed25519;
pub mod rand;
pub mod secp256k1;

pub trait PrivateKey {
    type PublicKey;

    fn public(&self) -> Self::PublicKey;
}
