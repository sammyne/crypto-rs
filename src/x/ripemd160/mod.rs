use vendored_ripemd160::{Digest, Ripemd160};

pub use crate::Hash;

pub type RIPEMD160 = Ripemd160;

pub const BLOCK_SIZE: usize = 64;
pub const SIZE: usize = 20;

impl Hash for RIPEMD160 {
    fn size() -> usize {
        Ripemd160::output_size()
    }

    fn block_size() -> usize {
        BLOCK_SIZE
    }

    fn reset(&mut self) {
        Digest::reset(self);
    }

    fn sum(&mut self) -> Vec<u8> {
        self.clone().result().as_slice().to_vec()
    }
}

pub fn new() -> RIPEMD160 {
    Digest::new()
}

pub fn sum(b: &[u8]) -> [u8; SIZE] {
    let d = Ripemd160::digest(b);

    let mut out = [0u8; SIZE];
    out.copy_from_slice(d.as_slice());

    out
}
