use std::io::{Read, Write};

mod keccak256;
mod keccak512;
mod shake128;
mod shake256;
mod sum224;
mod sum256;
mod sum384;
mod sum512;

pub use crate::Hash;

pub use keccak256::*;
pub use keccak512::*;
pub use shake128::*;
pub use shake256::*;
pub use sum224::*;
pub use sum256::*;
pub use sum384::*;
pub use sum512::*;

pub trait ShakeHash: Clone + Read + Write {
    /// reset resets the Hash to its initial state
    fn reset(&mut self);
}
