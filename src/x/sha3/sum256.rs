use sha3::{Digest, Sha3_256};

use super::Hash;

pub type SHA3_256 = Sha3_256;

pub const BLOCK_SIZE256: usize = 136;
pub const SIZE256: usize = 32;

impl Hash for SHA3_256 {
    fn new() -> Self {
        Digest::new()
    }

    fn size() -> usize {
        Sha3_256::output_size()
    }

    fn block_size() -> usize {
        BLOCK_SIZE256
    }

    fn reset(&mut self) {
        Digest::reset(self);
    }

    fn sum(&mut self) -> Vec<u8> {
        let d = self.clone().result();
        let mut out = Vec::with_capacity(d.as_slice().len());
        out.extend_from_slice(d.as_slice());

        out
    }
}

pub fn new256() -> SHA3_256 {
    Hash::new()
}

pub fn sum256(b: &[u8]) -> [u8; SIZE256] {
    let d = Sha3_256::digest(b);

    let mut out = [0u8; SIZE256];
    (&mut out[..]).copy_from_slice(d.as_slice());

    out
}
