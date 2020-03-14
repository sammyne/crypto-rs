use sha2::{Digest, Sha224, Sha256};

pub use crate::Hash;

pub type SHA224 = Sha224;
pub type SHA256 = Sha256;

pub const BLOCK_SIZE: usize = 64;
pub const SIZE: usize = 32;
pub const SIZE224: usize = 28;

impl Hash for SHA224 {
    fn size() -> usize {
        Sha224::output_size()
    }

    fn block_size() -> usize {
        BLOCK_SIZE
    }

    fn reset(&mut self) {
        Digest::reset(self)
    }

    fn sum(&mut self) -> Vec<u8> {
        self.clone().result().as_slice().to_vec()
    }
}

impl Hash for SHA256 {
    fn size() -> usize {
        Sha256::output_size()
    }

    fn block_size() -> usize {
        BLOCK_SIZE
    }

    fn reset(&mut self) {
        Digest::reset(self)
    }

    fn sum(&mut self) -> Vec<u8> {
        self.clone().result().as_slice().to_vec()
    }
}

pub fn new() -> SHA256 {
    Sha256::new()
}

pub fn new224() -> SHA224 {
    Sha224::new()
}

pub fn sum224(b: &[u8]) -> [u8; SIZE224] {
    let d = Sha224::digest(b);

    let mut out = [0u8; SIZE224];
    (&mut out[..]).copy_from_slice(d.as_slice());

    out
}

pub fn sum256(b: &[u8]) -> [u8; SIZE] {
    let d = Sha256::digest(b);

    let mut out = [0u8; SIZE];
    (&mut out[..]).copy_from_slice(d.as_slice());

    out
}
